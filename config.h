//The DBus busname to own
#define USER_MANAGER_BUSNAME "xyz.openbmc_project.User.Manager"

//The default crypt algorithm if one not found in shadow
#define DEFAULT_CRYPT_ALGO 1

//Class version to register with Cereal
#define CLASS_VERSION  1

//Path of LDAP configuration file
#define LDAP_CONFIG_FILE "/etc/nslcd.conf"

//Path of LDAP server CA certificate
#define TLS_CACERT_PATH "/etc/ssl/certs/authority"

//Path of LDAP client certificate
#define TLS_CERT_FILE "/etc/nslcd/certs/cert.pem"

//LDAP configuration root
#define LDAP_CONFIG_ROOT "/xyz/openbmc_project/user/ldap"

//D-Bus path of LDAP config object
#define LDAP_CONFIG_DBUS_OBJ_PATH "/xyz/openbmc_project/user/ldap/config"

//D-Bus busname of LDAP config service
#define LDAP_CONFIG_BUSNAME "xyz.openbmc_project.Ldap.Config"

//path of directory having persisted LDAP configuration enabled property
#define LDAP_CONF_PERSIST_PATH "/var/lib/phosphor-ldap-conf"

//systemd busname
#define SYSTEMD_BUSNAME "org.freedesktop.systemd1"

//systemd path
#define SYSTEMD_PATH "/org/freedesktop/systemd1"

//systemd interface
#define SYSTEMD_INTERFACE "org.freedesktop.systemd1.Manager"
