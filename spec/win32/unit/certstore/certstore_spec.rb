#
# Author:: Piyush Awasthi (<piyush.awasthi@msystechnologies.com>)
# Copyright:: Copyright (c) 2017 Chef Software, Inc.
# License:: Apache License, Version 2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

require 'spec_helper'

describe Win32::Certstore do

  let (:certstore) { Win32::Certstore }
  let (:certbase) { Win32::Certstore::StoreBase }
  
  describe "#list" do
    context "When passing empty certificate store name" do
      let (:store_name) { "" }
      it "Raise ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError)
      end
    end

    context "When passing invalid certificate store name" do
      let (:store_name) { "Chef" }
      it "Raise ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError)
      end
    end

    context "When passing empty certificate store name" do
      let (:store_name) { nil }
      it "Raise ArgumentError" do
        expect { certstore.open(store_name) }.to raise_error(ArgumentError)
      end
    end

    context "When passing valid certificate store name" do
      let (:store_name) { "root" }
      let (:root_certificate_name) { "Microsoft Root Certificate Authority"}
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_list).and_return([root_certificate_name])
      end
      it "return certificate list" do
        store = certstore.open(store_name)
        certificate_list = store.list
        expect(certificate_list.size).to eql(1)
        expect(certificate_list.first).to eql root_certificate_name
      end
    end

    context "When passing valid certificate store name" do
      let (:store_name) { "root" }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:cert_list).and_return([])
      end
      it "return no certificate list" do
        store = certstore.open(store_name)
        certificate_list = store.list
        expect(certificate_list.size).to eql(0)
      end
    end

    context "When adding invalid certificate" do
      let (:store_name) { "root" }
      let (:cert_file_path) { '.\win32\unit\assets\test.cer' }
      it "return no certificate list" do
        allow(certbase).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        store = certstore.open(store_name)
        expect { store.add(cert_file_path) }.to raise_error(Chef::Exceptions::Win32APIError)
      end
    end

    context "When deleting valid certificate" do
      let (:store_name) { "ca" }
      let (:certificate_name) { 'GeoTrust Global CA' }
      before(:each) do
        allow_any_instance_of(certbase).to receive(:CertDeleteCertificateFromStore).and_return(true)
      end
      it "return message of successful deletion" do
        store = certstore.open(store_name)
        delete_cert = store.delete(certificate_name)
        expect(delete_cert).to eq("Deleted certificate GeoTrust Global CA successfully")
      end
    end

    context "When deleting invalid certificate" do
      let (:store_name) { "my" }
      let (:certificate_name) { "tmp_cert.mydomain.com" }
      it "return message of `Cannot find certificate`" do
        allow(certbase).to receive(:CertDeleteCertificateFromStore).and_return(false)
        store = certstore.open(store_name)
        delete_cert = store.delete(certificate_name)
        expect(delete_cert).to eq("Cannot find certificate with name as `tmp_cert.mydomain.com`. Please re-verify certificate Issuer name or Friendly name")
      end
    end

    context "When passing empty certificate_name to delete it" do
      let (:store_name) { "my" }
      let (:certificate_name) { "" }
      it "return message of `Cannot find certificate`" do
        allow(certbase).to receive(:CertDeleteCertificateFromStore).and_return(false)
        store = certstore.open(store_name)
        delete_cert = store.delete(certificate_name)
        expect(delete_cert).to eq("Cannot find certificate with name as ``. Please re-verify certificate Issuer name or Friendly name")
      end
    end

    context "When adding or deleting certificate failed with FFI::LastError" do
      let (:store_name) { "root" }
      let (:cert_file_path) { '.\win32\unit\assets\test.cer' }
      let (:certificate_name) { "Microsoft Root Certificate Authority" }
      
      it "return 'The operation was canceled by the user'" do
        allow(certbase).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(1223)
        store = certstore.open(store_name)
        expect { store.add(cert_file_path) }.to raise_error(Chef::Exceptions::Win32APIError)
      end

      it "return 'Cannot find object or property'" do
        allow(certbase).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2146885628)
        store = certstore.open(store_name)
        expect { store.add(cert_file_path) }.to raise_error(Chef::Exceptions::Win32APIError)
      end

      it "return 'An error occurred while reading or writing to a file'" do
        allow(certbase).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2146885629)
        store = certstore.open(store_name)
        expect { store.add(cert_file_path) }.to raise_error(Chef::Exceptions::Win32APIError)
      end

      it "return 'ASN1 bad tag value met. -- Is the certificate in DER format?'" do
        allow(certbase).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2146881269)
        store = certstore.open(store_name)
        expect { store.add(cert_file_path) }.to raise_error(Chef::Exceptions::Win32APIError)
      end

      it "return 'ASN1 unexpected end of data'" do
        allow(certbase).to receive(:CertAddEncodedCertificateToStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2146881278)
        store = certstore.open(store_name)
        expect { store.add(cert_file_path) }.to raise_error(Chef::Exceptions::Win32APIError)
      end

      it "return 'System.UnauthorizedAccessException, Access denied..'" do
        allow(certbase).to receive(:CertDeleteCertificateFromStore).and_return(false)
        allow(FFI::LastError).to receive(:error).and_return(-2147024891)
        store = certstore.open(store_name)
        expect { store.delete(certificate_name) }.to raise_error(Chef::Exceptions::Win32APIError)
      end
    end
  end
end
