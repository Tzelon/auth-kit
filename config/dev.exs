import Config

# Loaded only for MIX_ENV=dev in this repo. Host apps set their own keys.
config :auth_kit,
  token_encryption_keys: %{1 => "JFW09y63mKSSrggag4otLvSxTn8xTS/H6e26aZbqypA="}
