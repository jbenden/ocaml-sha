/*
 *	Copyright (C) 2017 Joseph Benden <joe@benden.us>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; version 2.1 or version 3.0 only.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE
#include <string.h>
#include "sha1dc/sha1.h"


/* this part implement the OCaml binding */
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/custom.h>
#include <caml/fail.h>
#include <caml/bigarray.h>
#include <caml/threads.h>

#define GET_CTX_STRUCT(a) ((SHA1_CTX *) a)

CAMLexport value stub_sha1dc_init(value unit)
{
	CAMLparam1(unit);
	CAMLlocal1(result);

	result = caml_alloc(sizeof(SHA1_CTX), Abstract_tag);
	SHA1DCInit(GET_CTX_STRUCT(result));

	CAMLreturn(result);
}

CAMLprim value stub_sha1dc_update(value ctx, value data, value ofs, value len)
{
	CAMLparam4(ctx, data, ofs, len);

	SHA1DCUpdate(GET_CTX_STRUCT(ctx), (const char *) data + Int_val(ofs),
	            Int_val(len));

	CAMLreturn(Val_unit);
}

CAMLprim value stub_sha1dc_update_bigarray(value ctx, value buf)
{
	CAMLparam2(ctx, buf);
	SHA1_CTX ctx_dup;
	const char *data = Data_bigarray_val(buf);
	size_t len = Bigarray_val(buf)->dim[0];

	ctx_dup = *GET_CTX_STRUCT(ctx);
	caml_release_runtime_system();
	SHA1DCUpdate(&ctx_dup, data, len);
	caml_acquire_runtime_system();
	*GET_CTX_STRUCT(ctx) = ctx_dup;

	CAMLreturn(Val_unit);
}


CAMLprim value stub_sha1dc_finalize(value ctx)
{
	CAMLparam1(ctx);
	CAMLlocal1(result);

	result = caml_alloc_string(20);
	SHA1DCFinal((unsigned char *) result, GET_CTX_STRUCT(ctx));

	CAMLreturn(result);
}
