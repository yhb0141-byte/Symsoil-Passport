idf_component_register(
    SRCS "main.c"
         "passport_core.c"
         "passport_protocol.c"
         "passport_crypto_mbedtls.c"
         "passport_vectors.c"
         "passport_outbox.c"
         "passport_outbox_nvs.c"
         "passport_transport.c"
    INCLUDE_DIRS "."
    REQUIRES bsp esp_timer mbedtls nvs_flash
)
