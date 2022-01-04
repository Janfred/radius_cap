# frozen_string_literal: true

require_relative '../src/tlsciphersuites'
describe TLSCipherSuite do
  before do
    @mixed_pfs = TLSCipherSuite.new([
                                      [0xC0, 0x2B], # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                                      [0x00, 0x2F]  # TLS_RSA_WITH_AES_128_CBC_SHA
                                    ])
    @only_pfs = TLSCipherSuite.new([
                                     [0xC0, 0x14], # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
                                     [0xC0, 0x23]  # TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
                                   ])
    @no_pfs = TLSCipherSuite.new([
                                   [0x00, 0x2F], # TLS_RSA_WITH_AES_128_CBC_SHA
                                   [0x00, 0x35]  # TLS_RSA_WITH_AES_256_CBC_SHA
                                 ])
  end
  describe '.pfs_avail?' do
    context 'given a Cipher Set with mixed (PFS and non-PFS) cipher suites' do
      it 'should return true' do
        expect(@mixed_pfs.pfs_avail?).to be true
      end
    end
    context 'given a Cipher Set with only PFS cipher suites' do
      it 'should return true' do
        expect(@only_pfs.pfs_avail?).to be true
      end
    end
    context 'given a Cipher Set with only non-PFS cipher suites' do
      it 'should return false' do
        expect(@no_pfs.pfs_avail?).to be false
      end
    end
  end
  describe '.only_pfs?' do
    context 'given a Cipher Set with mixed (PFS and non-PFS) cipher suites' do
      it 'should return false' do
        expect(@mixed_pfs.only_pfs?).to be false
      end
    end
    context 'given a Cipher Set with only PFS cipher suites' do
      it 'should return true' do
        expect(@only_pfs.only_pfs?).to be true
      end
    end
    context 'given a Cipher Set with only non-PFS cipher suites' do
      it 'should return false' do
        expect(@no_pfs.only_pfs?).to be false
      end
    end
  end
end
