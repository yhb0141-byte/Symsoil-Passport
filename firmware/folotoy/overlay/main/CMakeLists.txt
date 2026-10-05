idf_component_register(
    SRCS "main.c" "passport_core.c"
    INCLUDE_DIRS "."
    REQUIRES bsp esp_timer
)
