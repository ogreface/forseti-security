# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Rules engine for Geofencing."""
from collections import namedtuple
import itertools
import re

from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.util.regular_exp import escape_and_globify
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors
import pprint

LOGGER = logger.get_logger(__name__)


class InstanceGeofencingRulesEngine(bre.BaseRulesEngine):
    """Rules engine for InstanceGeofencingRules."""

    def __init__(self, rules_file_path, snapshot_timestamp=None):
        """Initialize.

        Args:
            rules_file_path (str): file location of rules
            snapshot_timestamp (str): timestamp for database.
        """
        super(InstanceGeofencingRulesEngine,
              self).__init__(rules_file_path=rules_file_path)
        self.rule_book = None

    def build_rule_book(self, global_configs=None):
        """Build InstanceGeofencingRuleBook from rules definition file.

        Args:
            global_configs (dict): Global Configs
        """
        self.rule_book = InstanceGeofencingRuleBook(
            self._load_rule_definitions())

    def find_violations(self, instance, force_rebuild=False):
        """Determine whether the instance rules.

        Args:
            instance (object): object of Instance type
            force_rebuild (bool): set to false to not force a rebuild

        Return:
            list: iterator of all violations
        """
        violations = itertools.chain()
        if self.rule_book is None or force_rebuild:
            self.build_rule_book()
        resource_rules = self.rule_book.get_resource_rules()

        for rule in resource_rules:
            violations = itertools.chain(violations,
                                         rule.find_violations(
                                             instance))
        return violations

    def add_rules(self, rules):
        """Add rules to the rule book.

        Args:
            rules (dicts): rule definitions
        """
        if self.rule_book is not None:
            self.rule_book.add_rules(rules)


class InstanceGeofencingRuleBook(bre.BaseRuleBook):
    """The RuleBook for enforced networks resources."""

    def __init__(self,
                 rule_defs=None):
        """Initialize.

        Args:
            rule_defs (dict): The parsed dictionary of rules from the YAML
                definition file.
        """
        super(InstanceGeofencingRuleBook, self).__init__()
        self.resource_rules_map = {}
        if not rule_defs:
            self.rule_defs = {}
        else:
            self.rule_defs = rule_defs
            self.add_rules(rule_defs)

    def add_rules(self, rule_defs):
        """Add rules to the rule book.

        Args:
            rule_defs (dict): rules definitions
        """
        for (i, rule) in enumerate(rule_defs.get('rules', [])):
            self.add_rule(rule, i)

    def add_rule(self, rule_def, rule_index):
        """Add a rule to the rule book.

        Add a rule to the rule book.

        The rule supplied to this method is the dictionary parsed from
        the rules definition file.

        For example, this rule...

        # rules yaml:
            rules:
          - name: all networks covered in whitelist
            project: '*'
            label-key: 'geofence'

        ... gets parsed into:
        {
            "rules": [
                {
                    "name": "all instances are appropriately geofenced",
                    "project": "*",
                    "label-key": "geofence"
                }
            ]
        }

        Args:
            rule_def (dict): A dictionary containing rule definition properties.
            rule_index (int): The index of the rule from the rule definitions.
                Assigned automatically when the rule book is built.
        """
        project = rule_def.get('project')
        label_key = rule_def.get('label-key')

        if (project is None) or (label_key is None):
            raise audit_errors.InvalidRulesSchemaError(
                'Faulty rule {}'.format(rule_def.get('name')))

        rule_def_resource = {'project': escape_and_globify(project),
                             'label_key': label_key}

        rule = Rule(rule_name=rule_def.get('name'),
                    rule_index=rule_index,
                    rules=rule_def_resource)

        resource_rules = self.resource_rules_map.get(rule_index)
        if not resource_rules:
            self.resource_rules_map[rule_index] = rule

    def get_resource_rules(self):
        """Get all the resource rules.

        Return:
            list: resource_rules_map values
        """
        return self.resource_rules_map.values()


class Rule(object):
    """The rules class for instance geofencing."""

    def __init__(self, rule_name, rule_index, rules):
        """Initialize.

        Args:
            rule_name (str): Name of the loaded rule
            rule_index (int): The index of the rule from the  definitions
            rules (dict): The resources associated with the rules like
                the whitelist
        """
        self.rule_name = rule_name
        self.rule_index = rule_index
        self.rules = rules

    def find_violations(self, instance):
        """Raise violation is the ip is not in the whitelist.

        Args:
            instance object

         Yields:
            namedtuple: Returns RuleViolation named tuple
        """
        pp = pprint.PrettyPrinter(indent=2)
        LOGGER.debug(pp.pformat(instance.labels))
        LOGGER.debug(self.rules)
        key_to_find = self.rules['label_key']
        LOGGER.debug("Key we're looking for: " + str(key_to_find))
        if instance.labels and (key_to_find in instance.labels):
            found_zone = str(instance.key.zone)
            expected_zone = instance.labels[key_to_find]
            LOGGER.debug("Instance should be in " + expected_zone)
            LOGGER.debug("Instance actually in " + found_zone)
            if expected_zone != found_zone:
                yield self.RuleViolation(
                    resource_name=instance.name,
                    resource_type=resource_mod.ResourceType.INSTANCE,
                    resource_id=instance.name,
                    full_name=instance.full_name,
                    rule_name=self.rule_name,
                    rule_index=self.rule_index,
                    violation_type='INSTANCE_GEOFENCE_VIOLATION',
                    violation_data="Expected {}, found {}".format(instance.labels[key_to_find], instance.key.zone),
                    resource_data=instance.json)
        else:
            LOGGER.debug("No label found for " + key_to_find)

    RuleViolation = namedtuple('RuleViolation',
                               ['resource_type', 'resource_id', 'full_name',
                                'rule_name', 'rule_index', 'violation_type',
                                'violation_data','resource_data', 'resource_name'])
