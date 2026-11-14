# frozen_string_literal: true

# SPDX-License-Identifier: Apache-2.0

require 'glazed/dialects/awplus'

RSpec.describe Glazed::Dialects::Awplus do
  it_behaves_like 'a dialect simulation', 'awplus/x230', transport: 'ssh'

  describe 'prompt' do
    it 'matches the exec and configure mode prompts' do
      ["awplus>", "awplus# ", "awplus(config)#", "awplus(config-if)# ", "awplus(config-vlan)#"].each do |line|
        expect(described_class.prompt_pattern).to match(line)
      end
    end

    it 'does not match command output' do
      expect(described_class.prompt_pattern).not_to match(" password abc#")
    end
  end
end
