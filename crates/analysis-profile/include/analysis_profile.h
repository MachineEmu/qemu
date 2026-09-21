#ifndef ANALYSIS_PROFILE_H
#define ANALYSIS_PROFILE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Returns a newly allocated validated JSON string, or NULL on failure. */
char *analysis_profile_validate_json(const unsigned char *input, size_t length);

/* Releases a string returned by analysis_profile_validate_json. */
void analysis_profile_free_string(char *value);

#ifdef __cplusplus
}
#endif

#endif
