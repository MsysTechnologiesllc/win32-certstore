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

require 'mixin/crypto'
require 'openssl'

module Win32
  class Certstore
    module StoreBase
      include Win32::Mixin::Crypto
      include Win32::Mixin::Assertions
      include Chef::Mixin::WideString
      include Chef::Mixin::ShellOut

      def cert_list(store_handler)
        cert_name = FFI::MemoryPointer.new(2, 128)
        cert_list = []
        begin
          while (pCertContext = CertEnumCertificatesInStore(store_handler, pCertContext) and not pCertContext.null? ) do
            if (CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil, cert_name, 1024))
              cert_list << cert_name.read_wstring
            end
          end
          CertFreeCertificateContext(pCertContext)
        rescue Exception => e
          @error = "load"
          lookup_error
        end
        cert_list.to_json
      end
      
      def cert_add(store_handler, cert_file_path)
        validate_certificate(cert_file_path)
        file_content = read_certificate_content(cert_file_path)
        pointer_cert = FFI::MemoryPointer.from_string(file_content)
        cert_length = file_content.bytesize
        begin
          if (CertAddEncodedCertificateToStore(store_handler, X509_ASN_ENCODING, pointer_cert, cert_length, 2, nil))
            return "Added certificate #{File.basename(cert_path)} successfully"
          else
            lookup_error
          end
        rescue Exception => e
          @error = "add"
          lookup_error
        end
      end

      def cert_delete(store_handler, certificate_name)
        cert_name = FFI::MemoryPointer.new(2, 128)
        delete_flag = 0
        begin
          while (pCertContext = CertEnumCertificatesInStore(store_handler, pCertContext) and not pCertContext.null? ) do
            if (CertGetNameStringW(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, CERT_NAME_ISSUER_FLAG, nil, cert_name, 1024))
              if( cert_name.read_wstring.downcase == certificate_name.downcase )
                if(CertDeleteCertificateFromStore(CertDuplicateCertificateContext(pCertContext)))
                  delete_flag = 1
                  return "Deleted certificate #{certificate_name} successfully"
                else
                  lookup_error
                end
              end
            end
          end
          return "Cannot find certificate with name as `#{certificate_name}`. Please re-verify certificate Issuer name or Friendly name" if delete_flag == 0
        rescue Exception => e
          @error = "delete: "
          lookup_error
        end
      end

      private

      def lookup_error
        last_error = FFI::LastError.error
        case last_error
        when 1223
          raise Chef::Exceptions::Win32APIError, "The operation was canceled by the user. "
        when -2146885628
          raise Chef::Exceptions::Win32APIError, "Cannot find object or property."
        when -2146885629
          raise Chef::Exceptions::Win32APIError, "An error occurred while reading or writing to a file. "
        when -2146881269
          raise Chef::Exceptions::Win32APIError, "ASN1 bad tag value met. -- Is the certificate in DER format?"
        when -2146881278
          raise Chef::Exceptions::Win32APIError, "ASN1 unexpected end of data.  "
        when -2147024891
          raise Chef::Exceptions::Win32APIError, "System.UnauthorizedAccessException, Access denied.."
        else
          raise Chef::Exceptions::Win32APIError, "Unable to #{@error} certificate with error: #{last_error}."
        end
      end

      def read_certificate_content(cert_path)
        unless (File.extname(cert_path) == ".der")
          temp_file = shell_out("powershell.exe -Command $env:temp").stdout.strip.concat("\\TempCert.der")
          shell_out("powershell.exe -Command openssl x509 -in #{cert_path} -out #{temp_file} -outform DER")
          cert_path = temp_file
        end
        File.read("#{cert_path}")
      end

    end
  end
end
