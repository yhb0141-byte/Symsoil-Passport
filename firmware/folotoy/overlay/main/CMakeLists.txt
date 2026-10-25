idf_component_register(
    SRCS "main.c"
         "passport_core.c"
         "passport_protocol.c"
         "passport_crypto_mbedtls.c"
         "passport_vectors.c"
         "passport_outbox.c"
         "passport_outbox_nvs.c"
         "passport_transport.c"
         "passport_delivery.c"
         "passport_trust.c"
         "passport_provision.c"
         "passport_signer.c"
         "passport_review.c"
    INCLUDE_DIRS "."
    REQUIRES bsp esp_timer mbedtls nvs_flash
)
