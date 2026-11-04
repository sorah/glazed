# typed: strict
# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

# Derived from Oxidized (https://github.com/ytti/oxidized) lib/oxidized/model/edgeos.rb,
# Copyright 2013-2015 Saku Ytti, Samer Abdel-Hafez and Oxidized contributors,
# licensed under the Apache License, Version 2.0. Modified for the glazed dialect API.

require 'glazed/dialects/base'

module Glazed
  module Dialects
    # Ubiquiti EdgeOS (EdgeRouter, Vyatta based).
    #
    # Collects `show configuration`, the hierarchical form, as the other dialects do with their native configuration.
    # The login shell is vbash, whose prompt is `user@host:~$`, and `user@host#` in configure mode.
    class Edgeos < Base
      prompt(/^([\w.-]+@[\w.-]+(?::[~\w\/.-]*\$|#)\s?)$/)
      comment_prefix '# '

      filter_output { |output| output.gsub(/[ \t\r]+$/, '') }

      # A value is double-quoted when it has characters the CLI treats specially.
      VALUE = %q((?:"[^"]*"|\S+)) #: String

      # Credentials in any node of the tree: user passwords, BGP/OSPF/RIP/VRRP authentication, PPPoE, dynamic DNS,
      # IPsec pre-shared keys, RADIUS/TACACS secrets, SNMPv3 keys, WireGuard keys. Public keys (`public-keys NAME`
      # with `key`) are not secrets and stay. The keyword must be a whole word, so `disable-password-authentication`
      # is left alone.
      sensitive_pattern(
        /^[ \t]+(?:encrypted-password|plaintext-password|password|pre-shared-secret|md5-key|plaintext-key|encrypted-key|private-key|secret) (?<v>#{VALUE})$/,
      ) { it[:v] }

      # `community NAME {` is a secret only under `service snmp`; the route-map's `community { community-list 100 }`
      # and `set community` have no block, and `community-list` is a different keyword.
      sensitive_pattern(/^[ \t]+community (?<v>#{VALUE}) \{$/) { it[:v] }
      # Children are indented deeper than their parent, so the backreference keeps the match inside the block.
      sensitive_pattern(
        /^(?<i>[ \t]*)trap-target \S+ \{\n(?:\k<i>[ \t]+(?!community )[^\n]*\n)*?\k<i>[ \t]+community (?<v>#{VALUE})$/,
      ) { it[:v] }

      # The connection string carries the UNMS key.
      sensitive_pattern(
        /^(?<i>[ \t]*)unms \{\n(?:\k<i>[ \t]+(?!connection )[^\n]*\n)*?\k<i>[ \t]+connection (?<v>#{VALUE})$/,
      ) { it[:v] }

      # The archive URL can embed credentials (scp://user:password@host/path).
      sensitive_pattern(
        /^(?<i>[ \t]*)commit-archive \{\n(?:\k<i>[ \t]+(?!location )[^\n]*\n)*?\k<i>[ \t]+location (?<v>#{VALUE})$/,
      ) { it[:v] }

      runbook :get do |book|
        book.command('show version | no-more') { comment(it.output.gsub(/^Uptime:\s.+\n?/, '')) }
        book.command('show configuration | no-more')
      end

      communication :telnet do |config|
        config.username_prompt = /login:\s/
        config.password_prompt = /^Password:\s/
      end

      communication :ssh, :telnet do |config|
        config.pre_logout { |run| run.cli.write("exit\n") }
      end
    end
  end
end
