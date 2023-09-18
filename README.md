# Encrypted root partition utilities
Collection of small utilities to securely unlock and init [LUKS](https://gitlab.com/cryptsetup/cryptsetup/)-encrypted root partition in [Nebius cloud](https://nebius.com/) environment.
Key decryption utility is specifially designed to work in early boot environment.

Probably only works on Debian and its derivatives because they have a simplified key handling mechanism at boot.

## Utilities
### key_supplier
The purpose of this utility is to provide clear-text key to `cryptsetup open` in an automated fashion.
It accomplishes it by sending an encrypted key to [Nebius Cloud](https://nebius.com/) [Key Management Service](https://nebius.com/il/docs/kms/concepts/) (KMS),
which decrypts the data and sends back the clear-text key. The key then is fed via stdout to the helper, which unlock the partition.

The utility was designed to be called by cryptdisk helpers at early boot. 

**Options**

To make usage more practical in preboot automated environment, most of the parameters are read directly from VM Metadata.
The parameters are set as first-level keys (like `user-data`).

Most important are `kms-key-id` and `kms-aad`. The first has an identifier for the KMS key, while the other
holds [AAD context](https://nebius.com/il/docs/kms/concepts/encryption#add-context).
This parameter is a string which is mixed in with the key when the encryption is done, effectively making it part of the key.

Command-line options:
```
  -key string
    	Location of encrypted key file (default "/keyfile.enc.bin")
  -kmsid string
    	KMS key ID
```

### key_encrypter
A convenience utility to perform the initial key generation and encryption.

**Options**
```
  -encrypted-key string
    	Location of encrypted key file (output)
  -force-key-overwrite
    	Forces key overwrite even if the file is already present in the destination
  -key string
    	Location of key file (input)
  -key-aad string
    	Additional encryption context for KMS
  -kmsid string
    	KMS key ID
```

## Example usage
Both this guide and utilities themselves assume the root partition is already encrypted with plaintext key.

### Encrypted root decryption with KMS
1. [Create](https://nebius.com/il/docs/kms/operations/key#create) KMS key, note its ID.

2. Create VM instance, and put KMS key id into metadata key named `kms-key-id`.
Optionally add another metadata key `kms-aad` for extra protection, but beware that without this string the decryption is impossible.

3. Generate and encrypt a new key: `key_encrypter -encrypted-key=/boot/partition.key`

4. Tell system how to unlock that key in `/etc/crypttab`.
   `initramfs-tools` utility will take care of copying the binary later. The binary will be placed on the same path inside initrd.
   See [crypttab(5)](https://manpages.debian.org/testing/cryptsetup/crypttab.5.en.html) for explanations of each field.
   ```
   root_crypt UUID=<of root partition> -key=/boot/partition.key luks,discard,keyscript=/usr/local/bin/key_supplier,initramfs
   ```

5. Make sure the key is where the system can reach it in the early boot.
   For example, `initramfs-tools` can copy it on initrd generation with this hook placed in `/etc/initramfs-tools/hooks/copy_key`:
   ```shell
   #!/bin/sh
   if [ "$1" = "prereqs" ]; then echo; exit 0; fi
   . /usr/share/initramfs-tools/hook-functions
   copy_file binary /boot/partition.key
   ```

6. To make sure you can reach API, you need to set up networking in the early stages of boot.
   Place this script inside `/etc/initramfs-tools/scripts/local-top/`:
   <details>
   <summary>early_networking.sh</summary>
   
   ```shell
   #!/bin/sh
   PREREQ=""
   prereqs()
   {
       echo "$PREREQ"
   }
   case $1 in
       prereqs)
           prereqs
           exit 0
           ;;
   esac
   
   . /scripts/functions
   setup_networking() {
       # Brings up the interfaces, according to the config in kernel cmdline (the `ip=` kernel arg)
       # https://www.kernel.org/doc/html/v6.1/admin-guide/nfs/nfsroot.html
       configure_networking
   
       # Also need DNS resolution --
       _resolv="/etc/resolv.conf"
       # Set first available DNS
       for iface_conf_file in /run/net-*.conf
       do
           . "${iface_conf_file}"
           test -z ${IPV4DNS0} && continue
           echo "nameserver ${IPV4DNS0}" > "${_resolv}"
           break
       done
   
       # Fallback to Google public resolver -- which might not work if VM has no internet.
       test -e "${_resolv}" && exit 0
       echo "nameserver 8.8.8.8" > "${_resolv}"
   }
   
   setup_networking
   ```
   </details>

7. Last touch is to copy CA certificate bundle (`apt install ca-certificates` if you can't find it) so that SSL is working.
   Copy this into hooks dir (`/etc/initramfs-tools/hooks`) (make sure the script is marked as executable!):
   <details>
   <summary>copy_certs</summary>
   
   ```shell
   #!/bin/sh
   PREREQ=""
   prereqs()
   {
        echo "$PREREQ"
   }
   case $1 in
   prereqs)
        prereqs
        exit 0
        ;;
   esac
   
   . /usr/share/initramfs-tools/hook-functions
   copy_file certs /etc/ssl/certs/ca-certificates.crt
   ```
   </details>

8. Double check that hooks and scripts inside `/etc/initramfs-tools` are executable. Otherwise, they will be silently ignored.
9. Reboot. The system should get back to full multiuser environment completely unattended.
