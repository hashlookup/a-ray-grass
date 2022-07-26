/*
Copyright (c) 2014. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <yara/modules.h>
#include <string.h>
#include <fleur/fleur.h>

#define MODULE_NAME araygrass

// #define BF_PATH "/home/jlouis/Downloads/hashlookup-full.bloom"
#define BF_PATH_IN "/home/jlouis/Git/yara/test-in.bloom"
// If a filter already exist at this location, it will be overwritten
#define BF_PATH_OUT "/home/jlouis/Git/yara/test-out.bloom"

// BloomFilter global variable
BloomFilter *bf;

char* strtoupper(char* s) {
  assert(s != NULL);

  char* p = s;
  while (*p != '\0') {
    *p = toupper(*p);
    p++;
  }

  return s;
}

define_function(check_string)
{
  SIZED_STRING* s = sized_string_argument(1);
  int64_t topupperflag = integer_argument(1);
  int test = 0;
  if (topupperflag == (int64_t)1) {
    test = Check(bf, strtoupper(s->c_string), s->length);
  }else{
    test = Check(bf, s->c_string, s->length);
  }

  return_integer(test);
}

define_function(add_string)
{
  SIZED_STRING* s = sized_string_argument(1);
  int64_t topupperflag = integer_argument(1);
  int test = 0;
  if (topupperflag ==  (int64_t)1) {
    test = Add(bf, strtoupper(s->c_string), s->length);
  }else{
    test = Add(bf, s->c_string, s->length);
  }

  return_integer(test);
}

int module_initialize(YR_MODULE* module)
{
  FILE* in = fopen(BF_PATH_IN, "rb");
  if (in == NULL) {
      exit(EXIT_FAILURE);
  }

  bf = BloomFilterFromFile(in);
  fclose(in);

  return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module)
{
  if(bf->modified == 1){
    printf("saving\n");
    FILE* out; 
    out = fopen(BF_PATH_OUT, "wb");
    if (out == NULL) {
      return EXIT_FAILURE;
    }
    BloomFilterToFile(bf, out);
    fclose(out);
  }
  free(bf->v);
  free(bf->Data);
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{

  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}

begin_declarations;

  declare_function("check_string", "si", "i", check_string);
  declare_function("add_string", "si", "i", add_string);

end_declarations;