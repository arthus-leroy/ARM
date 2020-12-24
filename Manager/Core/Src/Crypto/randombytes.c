#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>

#include <sys/types.h>

#ifdef __EMSCRIPTEN__
# include <emscripten.h>
#endif

#include "Crypto/randombytes.h"
#ifndef RANDOMBYTES_CUSTOM_IMPLEMENTATION
# ifdef RANDOMBYTES_DEFAULT_IMPLEMENTATION
#  include "randombytes_internal.h"
# endif
# include "Crypto/randombytes_sysrandom.h"
#endif
#include "Crypto/common.h"

/* C++Builder defines a "random" macro */
#undef random

static const randombytes_implementation *implementation;

#ifndef RANDOMBYTES_DEFAULT_IMPLEMENTATION
# ifdef __EMSCRIPTEN__
#  define RANDOMBYTES_DEFAULT_IMPLEMENTATION NULL
# else
#  define RANDOMBYTES_DEFAULT_IMPLEMENTATION &randombytes_sysrandom_implementation
# endif
#endif

#ifdef __EMSCRIPTEN__
static const char *
javascript_implementation_name(void)
{
    return "js";
}

static uint32_t
javascript_random(void)
{
    return EM_ASM_INT_V({
        return Module.getRandomValue();
    });
}

static void
javascript_stir(void)
{
    EM_ASM({
        if (Module.getRandomValue === undefined) {
            try {
                var window_ = 'object' === typeof window ? window : self;
                var crypto_ = typeof window_.crypto !== 'undefined' ? window_.crypto : window_.msCrypto;
                var randomValuesStandard = function() {
                    var buf = new Uint32Array(1);
                    crypto_.getRandomValues(buf);
                    return buf[0] >>> 0;
                };
                randomValuesStandard();
                Module.getRandomValue = randomValuesStandard;
            } catch (e) {
                try {
                    var crypto = require('crypto');
                    var randomValueNodeJS = function() {
                        var buf = crypto['randomBytes'](4);
                        return (buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3]) >>> 0;
                    };
                    randomValueNodeJS();
                    Module.getRandomValue = randomValueNodeJS;
                } catch (e) {
                    throw 'No secure random number generator found';
                }
            }
        }
    });
}

static void
javascript_buf(void * const buf, const size_t size)
{
    unsigned char *p = (unsigned char *) buf;
    size_t         i;

    for (i = (size_t) 0U; i < size; i++) {
        p[i] = (unsigned char) randombytes_random();
    }
}
#endif

static void
randombytes_init_if_needed(void)
{
    if (implementation == NULL) {
#ifdef __EMSCRIPTEN__
        static randombytes_implementation javascript_implementation;
        javascript_implementation.implementation_name = javascript_implementation_name;
        javascript_implementation.random = javascript_random;
        javascript_implementation.stir = javascript_stir;
        javascript_implementation.buf = javascript_buf;
        implementation = &javascript_implementation;
#else
        implementation = RANDOMBYTES_DEFAULT_IMPLEMENTATION;
#endif
        randombytes_stir();
    }
}

void
randombytes_stir(void)
{
    randombytes_init_if_needed();
    if (implementation->stir != NULL) {
        implementation->stir();
    }
}

void
randombytes_buf(void * const buf, const size_t size)
{
    randombytes_init_if_needed();
    if (size > (size_t) 0U) {
        implementation->buf(buf, size);
    }
}
