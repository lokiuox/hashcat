/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha512.cl"
#endif

KERNEL_FQ void m01735_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  u32 s[128] = { 0 };

  salt_encode_utf16le_swap_S (salt_bufs[SALT_POS].salt_buf, s, salt_bufs[SALT_POS].salt_len);
  
  u32 salt_len = salt_bufs[SALT_POS].salt_len * 2;

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_global_utf16le_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha512_ctx_t ctx = ctx0;

    sha512_update_global_utf16le_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha512_update_global (&ctx, s, salt_len); 

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_M_SCALAR (r0, r1, r2, r3);
  }
}

KERNEL_FQ void m01735_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R0],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R1],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R2],
    digests_buf[DIGESTS_OFFSET].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  u32 s[128] = { 0 };
  
  salt_encode_utf16le_swap_S (salt_bufs[SALT_POS].salt_buf, s, salt_bufs[SALT_POS].salt_len);
  
  const u32 salt_len = salt_bufs[SALT_POS].salt_len * 2;

  sha512_ctx_t ctx0;

  sha512_init (&ctx0);

  sha512_update_global_utf16le_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha512_ctx_t ctx = ctx0;

    sha512_update_global_utf16le_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha512_update_global (&ctx, s, salt_len);

    sha512_final (&ctx);

    const u32 r0 = l32_from_64_S (ctx.h[7]);
    const u32 r1 = h32_from_64_S (ctx.h[7]);
    const u32 r2 = l32_from_64_S (ctx.h[3]);
    const u32 r3 = h32_from_64_S (ctx.h[3]);

    COMPARE_S_SCALAR (r0, r1, r2, r3);
  }
}
