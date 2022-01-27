"""
sentry_opsgenie.plugin
~~~~~~~~~~~~~~~~~~~~~~

:copyright: (c) 2015 by Sentry Team, see AUTHORS for more details.
:license: Apache 2.0, see LICENSE for more details.
"""
from __future__ import absolute_import

import logging
import sentry_opsgenie

from django import forms
from django.utils.html import escape
from requests import HTTPError

from sentry import http
from sentry.plugins.bases import notify
from sentry.utils import json


class OpsGenieOptionsForm(notify.NotificationConfigurationForm):
    api_key = forms.CharField(
        max_length=255,
        help_text='OpsGenie API key used for authenticating API requests',
        required=True,
    )
    recipients = forms.CharField(
        max_length=255,
        help_text='The user names of individual users or groups (comma seperated)',
        required=False,
    )
    alert_url = forms.CharField(
        max_length=255,
        label='OpsGenie Alert URL',
        widget=forms.TextInput(
            attrs={'class': 'span6', 'placeholder': 'e.g. https://api.opsgenie.com/v2/alerts'}),
        help_text='It must be visible to the Sentry server',
        required=True,
    )


class OpsGeniePlugin(notify.NotificationPlugin):
    author = 'Sentry Team'
    author_url = 'https://github.com/getsentry'
    resource_links = (
        ('Bug Tracker', 'https://github.com/getsentry/sentry-opsgenie/issues'),
        ('Source', 'https://github.com/getsentry/sentry-opsgenie'),
    )

    title = 'OpsGenie'
    slug = 'opsgenie'
    description = 'Create OpsGenie alerts out of notifications.'
    conf_key = 'opsgenie'
    version = sentry_opsgenie.VERSION
    project_conf_form = OpsGenieOptionsForm

    logger = logging.getLogger('sentry.plugins.opsgenie')

    def is_configured(self, project):
        return all((
            self.get_option(k, project)
            for k in ('api_key', 'alert_url')
        ))

    def get_form_initial(self, project=None):
        return {
            'alert_url': 'https://api.opsgenie.com/v2/alerts',
        }

    def _get_event_tags_payload_data(self, event_tags_items):
        return [
            '%s:%s' % (str(x).replace(',', ''), str(y).replace(',', ''))
            for x, y
            in event_tags_items
        ]

    def build_payload(self, group, event, triggering_rules):
        payload = {
            'message': f'View {group.get_absolute_url()}',
            'alias': 'sentry: %d' % group.id,  # Adding sentry id
            'source': 'Sentry',
            'details': {
                'Sentry ID': str(group.id),
                'Sentry Group': getattr(group, 'message_short', group.message).encode('utf-8'),
                'Checksum': group.checksum,
                'Project ID': group.project.slug,
                'Project Name': group.project.name,
                'Logger': group.logger,
                'Level': group.get_level_display(),
                'URL': group.get_absolute_url(),
                'Triggering Rules': json.dumps(triggering_rules),
            },
            'entity': group.culprit,
        }

        payload['tags'] = self._get_event_tags_payload_data(event.get_tags())

        return payload

    def _get_paginated_opsgenie_responses(self, url, json=None, headers=None):
        '''
        Get list of all JSON responses (after accumulating paginated data).
        '''
        responses = []
        resp = http.safe_urlopen(url, json=json, headers=headers)
        resp_json = resp.json()
        if not resp.ok:
            raise HTTPError('Unsuccessful response from OpsGenie: %s' % resp_json)
        responses.append(resp_json)
        # TODO = confirm that paging->next not populated in response if no more links
        while 'paging' in resp_json and 'next' in resp_json['paging']:
            resp = http.safe_urlopen(url, json=json, headers=headers)
            resp_json = resp.json()
            if not resp.ok:
                raise HTTPError('Unsuccessful response from OpsGenie: %s' % resp_json)
            responses.append(resp_json)
        return responses


    def notify_users(self, group, event, fail_silently=False, triggering_rules=None, **kwargs):
        if not self.is_configured(group.project):
            return

        api_key = self.get_option('api_key', group.project)
        recipients = self.get_option('recipients', group.project)
        alert_url = self.get_option('alert_url', group.project)

        payload = self.build_payload(group, event, triggering_rules)

        headers = {'Authorization': 'GenieKey ' + api_key}

        if recipients:
            payload['recipients'] = recipients

        self._get_paginated_opsgenie_responses(alert_url, json=payload, headers=headers)

        # Get alert ids paired with their Sentry ids (the alias field)
        # GET request as didn't supply data or json
        list_alerts_responses = self._get_paginated_opsgenie_responses('https://api.opsgenie.com/v2/alerts', headers=headers)
        alerts = [(alert['id'], alert['alias']) for response in list_alerts_responses for alert in response['data']]

        event_tags_items = event.get_tags()
        event_tags = dict(event_tags_items)
        for alert_id, sentry_id in alerts:
            if sentry_id == 'sentry: %d' % group.id:
                if 'PII_free_category' in event_tags:
                    # Update message with tag if available
                    self._get_paginated_opsgenie_responses(f'https://api.opsgenie.com/v2/alerts/{alert_id}/message', json={'message': event_tags['PII_free_category']}, headers=headers)

                # Add any Sentry tags missing in Opsgenie
                tags_payload = {'tags': self._get_event_tags_payload_data(event_tags_items)}
                self._get_paginated_opsgenie_responses(f'https://api.opsgenie.com/v2/alerts/{alert_id}/tags', json=tags_payload, headers=headers)
