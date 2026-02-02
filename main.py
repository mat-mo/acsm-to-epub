import sys
import os
import base64
import zipfile
from lxml import etree
from oscrypto import keys
from oscrypto.asymmetric import dump_private_key

import libadobe
import libadobeFulfill
import register_ADE_account
import ineptepub

def get_private_key_der():
    activation_path = libadobe.get_activation_xml_path()
    with open(activation_path, 'rb') as f:
        activationxml = etree.parse(f)
    
    adNS = lambda tag: '{%s}%s' % ('http://ns.adobe.com/adept', tag)
    pk_node = activationxml.find(".//%s" % adNS("privateLicenseKey"))
    if pk_node is None:
        raise Exception("Could not find privateLicenseKey in activation.xml")
        
    key_data = base64.b64decode(pk_node.text)
    # The first 26 bytes are a header, skip them to get the DER RSA key
    return key_data[26:]

def main():
    # Set current directory as base for libadobe files
    cwd = os.getcwd()
    libadobe.update_account_path(cwd)

    if not os.path.exists(libadobe.get_activation_xml_path()):
        print("Device not registered. Starting registration...")
        # register_ADE_account.main() uses input(), so it's interactive.
        try:
            register_ADE_account.main()
        except SystemExit:
            # register_ADE_account calls exit(1) on failure
            pass
            
        if not os.path.exists(libadobe.get_activation_xml_path()):
             print("Registration failed or was cancelled.")
             sys.exit(1)
        print("Registration complete.")

    if len(sys.argv) < 2:
        print("Usage: python main.py <path_to_acsm_file> [output_directory]")
        sys.exit(1)

    acsm_file = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.expanduser("~/Downloads")

    if not os.path.exists(acsm_file):
        print(f"File not found: {acsm_file}")
        sys.exit(1)

    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    print(f"Processing {acsm_file}...")
    
    success, response_str = libadobeFulfill.fulfill(acsm_file)
    if not success:
        print(f"Fulfillment failed: {response_str}")
        sys.exit(1)

    try:
        response = etree.fromstring(response_str.encode('utf-8'))
    except Exception as e:
        print(f"Error parsing fulfillment response: {e}")
        sys.exit(1)

    ns = {'adept': 'http://ns.adobe.com/adept', 'dc': 'http://purl.org/dc/elements/1.1/'}
    
    resource = response.find('.//adept:fulfillmentResult', ns)
    if resource is None:
        print("Error: Invalid response structure (no fulfillmentResult)")
        # Check for error tag
        error = response.find('.//adept:error', ns)
        if error is not None:
             print(f"Server returned error: {error.get('data', 'Unknown error')}")
        else:
             print(response_str)
        sys.exit(1)

    # Extract metadata
    title_node = resource.find('.//dc:title', ns)
    title = title_node.text if title_node is not None else "Unknown Book"
    
    # Extract download URL
    src_node = resource.find('.//adept:resourceItemInfo/adept:src', ns)
    if src_node is None:
        print("Error: Could not find download URL in response")
        sys.exit(1)
        
    download_url = src_node.text

    # Sanitize title for filename
    safe_title = "".join([c for c in title if c.isalpha() or c.isdigit() or c==' ']).strip()
    if not safe_title:
        safe_title = "output_book"
        
    encrypted_filename = os.path.join(output_dir, f"{safe_title}_encrypted.epub")
    decrypted_filename = os.path.join(output_dir, f"{safe_title}.epub")
    
    print(f"Downloading '{title}' to {encrypted_filename}...")
    code = libadobe.sendHTTPRequest_DL2FILE(download_url, encrypted_filename)
    if code != 200:
        print(f"Download failed with code {code}")
        sys.exit(1)

    # Inject rights.xml if not present
    print("Injecting license information...")
    try:
        # Extract licenseToken and wrap in rights
        license_token = resource.find('.//adept:licenseToken', ns)
        if license_token is not None:
            rights_xml = etree.Element("{http://ns.adobe.com/adept}rights", nsmap={"adept": "http://ns.adobe.com/adept"})
            # Need to deep copy or at least make sure it's a clean node
            from copy import deepcopy
            rights_xml.append(deepcopy(license_token))
            
            rights_str = '<?xml version="1.0" encoding="UTF-8"?>\n' + etree.tostring(rights_xml, encoding="utf-8", pretty_print=True).decode("utf-8")
            
            with zipfile.ZipFile(encrypted_filename, 'a') as zf:
                if 'META-INF/rights.xml' not in zf.namelist():
                    zf.writestr('META-INF/rights.xml', rights_str)
                    print("Successfully injected META-INF/rights.xml")
        else:
            print("No licenseToken found in response, skipping injection.")
    except Exception as e:
        print(f"Failed to inject license: {e}")

    print("Download complete. Decrypting...")
    
    # Verify the file is a valid zip/epub before attempting decryption
    try:
        with zipfile.ZipFile(encrypted_filename) as zf:
            if "META-INF/container.xml" not in zf.namelist():
                print("Warning: Downloaded file does not appear to be a valid EPUB (missing META-INF/container.xml).")
    except zipfile.BadZipFile:
        print("Error: The downloaded file is not a valid ZIP archive.")
        print("This often means the server returned an error (like 403 or 404) instead of the book.")
        print("Check the content of the file to see if it contains an error message.")
        sys.exit(1)

    try:
        userkey = get_private_key_der()
        res = ineptepub.decryptBook(userkey, encrypted_filename, decrypted_filename)
        
        if res == 0:
            print(f"Successfully created: {decrypted_filename}")
            # Optional: remove encrypted file
            # os.remove(encrypted_filename)
        elif res == 1:
            print(f"The book '{decrypted_filename}' appears to be already DRM-free.")
            print(f"Renaming {encrypted_filename} to {decrypted_filename}...")
            if os.path.exists(decrypted_filename):
                os.remove(decrypted_filename)
            os.rename(encrypted_filename, decrypted_filename)
            print("Done.")
        else:
            print("Decryption failed.")
    except Exception as e:
        print(f"Decryption error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
