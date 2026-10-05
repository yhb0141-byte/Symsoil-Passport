idf_component_register(
    SRCS "main.c"
         "passport_core.c"
         "passport_protocol.c"
         "passport_crypto_mbedtls.c"
         "passport_vectors.c"
    INCLUDE_DIRS "."
    REQUIRES bsp esp_timer mbedtls
)
