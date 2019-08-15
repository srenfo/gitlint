try:
    # python 2.x
    from ConfigParser import ConfigParser, Error as ConfigParserError
except ImportError:  # pragma: no cover
    # python 3.x
    from configparser import ConfigParser, Error as ConfigParserError  # pragma: no cover, pylint: disable=import-error

import copy
import io
import re
import os
import shutil

from collections import OrderedDict
from gitlint.utils import ustr, DEFAULT_ENCODING
from gitlint import rules  # For some weird reason pylint complains about this, pylint: disable=unused-import
from gitlint import options
from gitlint import rule_finder
from gitlint.contrib import rules as contrib_rules


def handle_option_error(func):
    """ Decorator that calls given method/function and handles any RuleOptionError gracefully by converting it to a
    LintConfigError. """

    def wrapped(*args):
        try:
            return func(*args)
        except options.RuleOptionError as e:
            raise LintConfigError(ustr(e))

    return wrapped


class LintConfigError(Exception):
    pass


class LintConfig(object):
    """ Class representing gitlint configuration.
        Contains active config and rules as well as number of methods to easily get/set the config.
    """

    RULE_QUALIFIER_SYMBOL = ":"

    # Default tuple of rule classes (tuple because immutable).
    default_rule_classes = (rules.IgnoreByTitle,
                            rules.IgnoreByBody,
                            rules.TitleMaxLength,
                            rules.TitleTrailingWhitespace,
                            rules.TitleLeadingWhitespace,
                            rules.TitleTrailingPunctuation,
                            rules.TitleHardTab,
                            rules.TitleMustNotContainWord,
                            rules.TitleRegexMatches,
                            rules.BodyMaxLineLength,
                            rules.BodyMinLength,
                            rules.BodyMissing,
                            rules.BodyTrailingWhitespace,
                            rules.BodyHardTab,
                            rules.BodyFirstLineEmpty,
                            rules.BodyChangedFileMention,
                            rules.AuthorValidEmail)

    def __init__(self):
        # Use an ordered dict so that the order in which rules are applied is always the same
        self._rules = OrderedDict()
        for rule_cls in self.default_rule_classes:
            self.add_rule(rule_cls, rule_cls.id)

        self._verbosity = options.IntOption('verbosity', 3, "Verbosity")
        self._ignore_merge_commits = options.BoolOption('ignore-merge-commits', True, "Ignore merge commits")
        self._ignore_fixup_commits = options.BoolOption('ignore-fixup-commits', True, "Ignore fixup commits")
        self._ignore_squash_commits = options.BoolOption('ignore-squash-commits', True, "Ignore squash commits")
        self._debug = options.BoolOption('debug', False, "Enable debug mode")
        self._extra_path = None
        target_description = "Path of the target git repository (default=current working directory)"
        self._target = options.PathOption('target', os.path.realpath(os.getcwd()), target_description)
        self._ignore = options.ListOption('ignore', [], 'List of rule-ids to ignore')
        self._contrib = options.ListOption('contrib', [], 'List of contrib-rules to enable')
        self._config_path = None
        ignore_stdin_description = "Ignore any stdin data. Useful for running in CI server."
        self._ignore_stdin = options.BoolOption('ignore-stdin', False, ignore_stdin_description)

    @property
    def target(self):
        return self._target.value if self._target else None

    @target.setter
    @handle_option_error
    def target(self, value):
        return self._target.set(value)

    @property
    def verbosity(self):
        return self._verbosity.value

    @verbosity.setter
    @handle_option_error
    def verbosity(self, value):
        self._verbosity.set(value)
        if self.verbosity < 0 or self.verbosity > 3:
            raise LintConfigError("Option 'verbosity' must be set between 0 and 3")

    @property
    def ignore_merge_commits(self):
        return self._ignore_merge_commits.value

    @ignore_merge_commits.setter
    @handle_option_error
    def ignore_merge_commits(self, value):
        return self._ignore_merge_commits.set(value)

    @property
    def ignore_fixup_commits(self):
        return self._ignore_fixup_commits.value

    @ignore_fixup_commits.setter
    @handle_option_error
    def ignore_fixup_commits(self, value):
        return self._ignore_fixup_commits.set(value)

    @property
    def ignore_squash_commits(self):
        return self._ignore_squash_commits.value

    @ignore_squash_commits.setter
    @handle_option_error
    def ignore_squash_commits(self, value):
        return self._ignore_squash_commits.set(value)

    @property
    def debug(self):
        return self._debug.value

    @debug.setter
    @handle_option_error
    def debug(self, value):
        return self._debug.set(value)

    @property
    def extra_path(self):
        return self._extra_path.value if self._extra_path else None

    @extra_path.setter
    def extra_path(self, value):
        try:
            if self.extra_path:
                self._extra_path.set(value)
            else:
                self._extra_path = options.PathOption(
                    'extra-path', value,
                    "Path to a directory or module with extra user-defined rules",
                    type='both'
                )

            # Make sure we unload any previously loaded extra-path rules
            for rule in self.rules:
                if hasattr(rule, 'is_user_defined') and rule.is_user_defined:
                    del self._rules[rule.id]

            # Find rules in the new extra-path
            rule_classes = rule_finder.find_rule_classes(self.extra_path)

            # Add the newly found rules to the existing rules
            for rule_class in rule_classes:
                self.add_rule(rule_class, rule_class.id, {"is_user_defined": True})

        except (options.RuleOptionError, rules.UserRuleError) as e:
            raise LintConfigError(ustr(e))

    @property
    def ignore(self):
        return self._ignore.value

    @ignore.setter
    def ignore(self, value):
        if value == "all":
            value = [rule.id for rule in self.rules]
        return self._ignore.set(value)

    @property
    def contrib(self):
        return self._contrib.value

    @contrib.setter
    def contrib(self, value):
        try:
            self._contrib.set(value)

            # Make sure we unload any previously loaded contrib rules when re-setting the value
            for rule in self.rules:
                if hasattr(rule, 'is_contrib') and rule.is_contrib:
                    del self._rules[rule.id]

            # Load all classes from the contrib directory
            contrib_dir_path = os.path.dirname(os.path.realpath(contrib_rules.__file__))
            rule_classes = rule_finder.find_rule_classes(contrib_dir_path)

            # For each specified contrib rule, check whether it exists among the contrib classes
            for rule_id_or_name in self.contrib:
                rule_class = next((rc for rc in rule_classes if
                                   rc.id == ustr(rule_id_or_name) or rc.name == ustr(rule_id_or_name)), False)

                # If contrib rule exists, instantiate it and add it to the rules list
                if rule_class:
                    self.add_rule(rule_class, rule_class.id, {"is_contrib": True})
                else:
                    raise LintConfigError(u"No contrib rule with id or name '{0}' found.".format(ustr(rule_id_or_name)))

        except (options.RuleOptionError, rules.UserRuleError) as e:
            raise LintConfigError(ustr(e))

    @property
    def ignore_stdin(self):
        return self._ignore_stdin.value

    @ignore_stdin.setter
    @handle_option_error
    def ignore_stdin(self, value):
        return self._ignore_stdin.set(value)

    @property
    def rules(self):
        # Create a new list based on _rules.values() because in python 3, values() is a ValuesView as opposed to a list
        return [rule for rule in self._rules.values()]

    def _get_unqualified_rule(self, rule_id_or_name):
        """ Retrieve rule that is known to not be qualified: i.e. it does not have a
            RULE_QUALIFIER_SYMBOL in its name """
        rule_id_or_name = ustr(rule_id_or_name)  # convert to unicode first
        # try finding rule by id
        rule = self._rules.get(rule_id_or_name)
        # if not found, try finding rule by name
        if not rule:
            rule = next((rule for rule in self._rules.values() if rule.name == rule_id_or_name), None)
        return rule

    @staticmethod
    def _get_canonical_rule_id(rule_class, name_specifier):
        return rule_class.id + LintConfig.RULE_QUALIFIER_SYMBOL + name_specifier

    def get_rule(self, rule_id_or_name):
        rule_name_parts = rule_id_or_name.split(self.RULE_QUALIFIER_SYMBOL, 1)
        # If the rule we're trying to fetch is qualified, then determine its canonical name first
        if len(rule_name_parts) > 1:  # qualified rule
            unqualified_rule = self._get_unqualified_rule(rule_name_parts[0])
            cannonical_rule_id = self._get_canonical_rule_id(unqualified_rule.__class__, rule_name_parts[1])
            return self._rules.get(cannonical_rule_id)

        # else:  # unqualified rule
        return self._get_unqualified_rule(rule_id_or_name)

    def add_rule(self, rule_class, rule_id, rule_attrs=None):
        """ Instantiates and adds a rule to the set of rules managed by this LintConfig.
            Note: There can be multiple instantiations of the same rule_class in the LintConfig, as long as there
            rule_id is unique.
            :param rule_class python class representing the rule
            :param rule_id unique identifier for the rule. If not unique, it will
                           overwrite the existing rule with that id
            :param rule_attrs dictionary of attributes to set on the instantiated rule obj
        """
        rule_obj = rule_class()
        rule_obj.id = rule_id
        if rule_attrs:
            for key, val in rule_attrs.items():
                setattr(rule_obj, key, val)
        self._rules[rule_obj.id] = rule_obj

    def add_qualified_rule(self, qualified_rule_id_or_name):
        """ Adds a new qualified rule to the LintConfig by looking up the rule_class identified by the first part of
            the qualified_rule_id_or_name (=the class-specifier), and then instantiating a new rule from that class,
            identifying it with the remainder (=the name-specifier) of the qualified_rule_id_or_name.
            Example:
                qualified_rule_id_or_name = "title-must-not-contain-word:my-user-defined-name"
                                            |        class-specifier    |    name-specifier  |
             -> this will add a rule 'T5:my-user-defined-name' to LingConfig.rules
             -> 'T5:my-user-defined-name' = canonical identifier for the TitleMustNotContainWord rule
        """
        rule_name_parts = qualified_rule_id_or_name.split(self.RULE_QUALIFIER_SYMBOL, 1)
        unqualified_rule = self._get_unqualified_rule(rule_name_parts[0])
        cannonical_rule_id = self._get_canonical_rule_id(unqualified_rule.__class__, rule_name_parts[1])
        self.add_rule(unqualified_rule.__class__, cannonical_rule_id)

    def _get_option(self, rule_name_or_id, option_name):
        rule_name_or_id = ustr(rule_name_or_id)  # convert to unicode first
        option_name = ustr(option_name)
        rule = self.get_rule(rule_name_or_id)
        if not rule:
            raise LintConfigError(u"No such rule '{0}'".format(rule_name_or_id))

        option = rule.options.get(option_name)
        if not option:
            raise LintConfigError(u"Rule '{0}' has no option '{1}'".format(rule_name_or_id, option_name))

        return option

    def get_rule_option(self, rule_name_or_id, option_name):
        """ Returns the value of a given option for a given rule. LintConfigErrors will be raised if the
        rule or option don't exist. """
        option = self._get_option(rule_name_or_id, option_name)
        return option.value

    def set_rule_option(self, rule_name_or_id, option_name, option_value):
        """ Attempts to set a given value for a given option for a given rule.
            LintConfigErrors will be raised if the rule or option don't exist or if the value is invalid. """
        option = self._get_option(rule_name_or_id, option_name)
        try:
            option.set(option_value)
        except options.RuleOptionError as e:
            msg = u"'{0}' is not a valid value for option '{1}.{2}'. {3}."
            raise LintConfigError(msg.format(option_value, rule_name_or_id, option_name, ustr(e)))

    def set_general_option(self, option_name, option_value):
        attr_name = option_name.replace("-", "_")
        # only allow setting general options that exist and don't start with an underscore
        if not hasattr(self, attr_name) or attr_name[0] == "_":
            raise LintConfigError(u"'{0}' is not a valid gitlint option".format(option_name))

        # else:
        setattr(self, attr_name, option_value)

    def __eq__(self, other):
        return isinstance(other, LintConfig) and \
               self.rules == other.rules and \
               self.verbosity == other.verbosity and \
               self.target == other.target and \
               self.extra_path == other.extra_path and \
               self.contrib == other.contrib and \
               self.ignore_merge_commits == other.ignore_merge_commits and \
               self.ignore_fixup_commits == other.ignore_fixup_commits and \
               self.ignore_squash_commits == other.ignore_squash_commits and \
               self.ignore_stdin == other.ignore_stdin and \
               self.debug == other.debug and \
               self.ignore == other.ignore and \
               self._config_path == other._config_path  # noqa

    def __str__(self):
        # config-path is not a user exposed variable, so don't print it under the general section
        return_str = u"config-path: {0}\n".format(self._config_path)
        return_str += u"[GENERAL]\n"
        return_str += u"extra-path: {0}\n".format(self.extra_path)
        return_str += u"contrib: {0}\n".format(self.contrib)
        return_str += u"ignore: {0}\n".format(",".join(self.ignore))
        return_str += u"ignore-merge-commits: {0}\n".format(self.ignore_merge_commits)
        return_str += u"ignore-fixup-commits: {0}\n".format(self.ignore_fixup_commits)
        return_str += u"ignore-squash-commits: {0}\n".format(self.ignore_squash_commits)
        return_str += u"ignore-stdin: {0}\n".format(self.ignore_stdin)
        return_str += u"verbosity: {0}\n".format(self.verbosity)
        return_str += u"debug: {0}\n".format(self.debug)
        return_str += u"target: {0}\n".format(self.target)
        return_str += u"[RULES]\n"
        for rule in self.rules:
            return_str += u"  {0}: {1}\n".format(rule.id, rule.name)
            for option_name, option_value in sorted(rule.options.items()):
                if isinstance(option_value.value, list):
                    option_val_repr = ",".join(option_value.value)
                else:
                    option_val_repr = option_value.value
                return_str += u"     {0}={1}\n".format(option_name, option_val_repr)
        return return_str


class LintConfigBuilder(object):
    """ Factory class that can build gitlint config.
    This is primarily useful to deal with complex configuration scenarios where configuration can be set and overridden
    from various sources (typically according to certain precedence rules) before the actual config should be
    normalized, validated and build. Example usage can be found in gitlint.cli.
    """

    def __init__(self):
        self._config_blueprint = {}
        self._config_path = None

    def set_option(self, section, option_name, option_value):
        if section not in self._config_blueprint:
            self._config_blueprint[section] = {}
        self._config_blueprint[section][option_name] = option_value

    def set_config_from_commit(self, commit):
        """ Given a git commit, applies config specified in the commit message.
            Supported:
             - gitlint-ignore: all
        """
        for line in commit.message.body:
            pattern = re.compile(r"^gitlint-ignore:\s*(.*)")
            matches = pattern.match(line)
            if matches and len(matches.groups()) == 1:
                self.set_option('general', 'ignore', matches.group(1))

    def set_config_from_string_list(self, config_options):
        """ Given a list of config options of the form "<rule>.<option>=<value>", parses out the correct rule and option
        and sets the value accordingly in this factory object. """
        for config_option in config_options:
            try:
                config_name, option_value = config_option.split("=", 1)
                if not option_value:
                    raise ValueError()
                rule_name, option_name = config_name.split(".", 1)
                self.set_option(rule_name, option_name, option_value)
            except ValueError:  # raised if the config string is invalid
                raise LintConfigError(
                    u"'{0}' is an invalid configuration option. Use '<rule>.<option>=<value>'".format(config_option))

    def set_from_config_file(self, filename):
        """ Loads lint config from a ini-style config file """
        if not os.path.exists(filename):
            raise LintConfigError(u"Invalid file path: {0}".format(filename))
        self._config_path = os.path.realpath(filename)
        try:
            parser = ConfigParser()

            with io.open(filename, encoding=DEFAULT_ENCODING) as config_file:
                # readfp() is deprecated in python 3.2+, but compatible with 2.7
                parser.readfp(config_file, filename)  # pylint: disable=deprecated-method

            for section_name in parser.sections():
                for option_name, option_value in parser.items(section_name):
                    self.set_option(section_name, option_name, ustr(option_value))

        except ConfigParserError as e:
            raise LintConfigError(ustr(e))

    def build(self, config=None):
        """ Build a real LintConfig object by normalizing and validating the options that were previously set on this
        factory. """

        # If we are passed a config object, then rebuild that object instead of building a new lintconfig object from
        # scratch
        if not config:
            config = LintConfig()

        config._config_path = self._config_path

        # Set general options first as this might change the behavior or validity of the other options
        general_section = self._config_blueprint.get('general')
        if general_section:
            for option_name, option_value in general_section.items():
                config.set_general_option(option_name, option_value)

        for section_name, section_dict in self._config_blueprint.items():
            for option_name, option_value in section_dict.items():
                # Skip over the general section, as we've already done that above
                if section_name != "general":

                    # For any qualified rules we find: instantiate them in the config
                    # Needed as these extra instances of rules are not active by default
                    if config.RULE_QUALIFIER_SYMBOL in section_name:
                        config.add_qualified_rule(section_name)

                    config.set_rule_option(section_name, option_name, option_value)

        return config

    def clone(self):
        """ Creates an exact copy of a LintConfigBuilder.  """
        builder = LintConfigBuilder()
        builder._config_blueprint = copy.deepcopy(self._config_blueprint)
        builder._config_path = self._config_path
        return builder


GITLINT_CONFIG_TEMPLATE_SRC_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), "files/gitlint")


class LintConfigGenerator(object):
    @staticmethod
    def generate_config(dest):
        """ Generates a gitlint config file at the given destination location.
            Expects that the given ```dest``` points to a valid destination. """
        shutil.copyfile(GITLINT_CONFIG_TEMPLATE_SRC_PATH, dest)
