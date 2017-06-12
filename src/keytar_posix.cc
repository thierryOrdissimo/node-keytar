#include "keytar.h"

#include <gnome-keyring.h>
#include <stdio.h>

namespace keytar {

namespace {
    const GnomeKeyringPasswordSchema kGnomeSchema = {
      GNOME_KEYRING_ITEM_GENERIC_SECRET, {
        { "service", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
        { "account", GNOME_KEYRING_ATTRIBUTE_TYPE_STRING },
        { NULL }
      }
    };
}  // namespace

KEYTAR_OP_RESULT SetPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* errStr) {
  GnomeKeyringResult result = gnome_keyring_store_password_sync(
      &kGnomeSchema,
      NULL,  // Default keyring.
      (service + "/" + account).c_str(),  // Display name.
      password.c_str(),
      "service", service.c_str(),
      "account", account.c_str(),
      NULL);
  if (result != GNOME_KEYRING_RESULT_OK) {
    *errStr = std::string(gnome_keyring_result_to_message(result));
    return FAIL_ERROR;
  }

  return SUCCESS;
}
  
KEYTAR_OP_RESULT GetPassword(const std::string& service,
                             const std::string& account,
                             std::string* password,
                             std::string* errStr) {
  gchar* raw_passwords;
  GnomeKeyringResult result = gnome_keyring_find_password_sync(
     &kGnomeSchema,
     &raw_passwords,
     "service", service.c_str(),
     "account", account.c_str(),
     NULL);
  if (result != GNOME_KEYRING_RESULT_OK) {
    *errStr = std::string(gnome_keyring_result_to_message(result));
    return FAIL_ERROR;
  }
  if (raw_passwords == NULL)
    return FAIL_NONFATAL;
  *password = raw_passwords;
  gnome_keyring_free_password(raw_passwords);
  return SUCCESS;
}

KEYTAR_OP_RESULT DeletePassword(const std::string& service,
                                const std::string& account,
                                std::string* errStr) {
  GnomeKeyringResult result = gnome_keyring_delete_password_sync(
      &kGnomeSchema,
      "service", service.c_str(),
      "account", account.c_str(),
      NULL);

  if (result != GNOME_KEYRING_RESULT_OK) {
    *errStr = std::string(gnome_keyring_result_to_message(result));
    return FAIL_ERROR;
  }
  return SUCCESS;
}

KEYTAR_OP_RESULT FindPassword(const std::string& service,
                              std::string* password,
                              std::string* errStr) {
  gchar* raw_passwords;
  GnomeKeyringResult result = gnome_keyring_find_password_sync(
        &kGnomeSchema,
        &raw_passwords,
        "service", service.c_str(),
        NULL);
  if (result != GNOME_KEYRING_RESULT_OK){
    *errStr = std::string(gnome_keyring_result_to_message(result));
    return FAIL_ERROR;
  }
  if (raw_passwords == NULL)
    return FAIL_NONFATAL;

  *password = raw_passwords;
  gnome_keyring_free_password(raw_passwords);
  return SUCCESS;
}

}  // namespace keytar
