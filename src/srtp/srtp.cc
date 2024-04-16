#include "srtp.hh"

#include "uvgrtp/frame.hh"

#include "../crypto.hh"
#include "../debug.hh"
#include "base.hh"
#include "global.hh"
#include "uvgrtp/util.hh"

#include <cstring>
#include <iostream>

#define MAX_OFF 10000

uvgrtp::srtp::srtp(int rce_flags)
    : base_srtp(), authenticate_rtp_(rce_flags & RCE_SRTP_AUTHENTICATE_RTP) {}

uvgrtp::srtp::~srtp() {}

rtp_error_t uvgrtp::srtp::rekey_add_remote_srtp_ctx(uint8_t *key,
                                                    uint8_t *salt) {
  if (!(rce_flags_ & RCE_SRTP_KMNGMNT_USER)) {
    UVG_LOG_ERROR(
        "Rekeying is only supported with RCE_SRTP_KMNGMNT_USER flag.");
    return RTP_NOT_SUPPORTED;
  }
  if (!(rce_flags_ & RCE_RECEIVE_ONLY)) {
    UVG_LOG_ERROR(
        "rekey_add_remote_srtp_ctx must only be called on receiving streams!");
    return RTP_GENERIC_ERROR;
  }
  if (!authenticate_rtp_) {
    UVG_LOG_ERROR(
        "Rekeying is only supported with RCE_SRTP_AUTHENTICATE_RTP flag set.");
    return RTP_NOT_SUPPORTED;
  }
  if (rekeying_state == SwitchingToZero || rekeying_state == SwitchingToOne) {
    UVG_LOG_ERROR(
        "Can not add new SRTP keys while two sets are already active!");
    return RTP_GENERIC_ERROR;
  }
  auto &srtp_ctx =
      rekeying_state == OnlyZero ? get_remote_ctxs()[1] : get_remote_ctxs()[0];
  cleanup_context(srtp_ctx);
  if (init_srtp_context(srtp_ctx, type_, rce_flags_, key, salt) != RTP_OK) {
    UVG_LOG_ERROR("Error initializing new SRTP context");
    return RTP_GENERIC_ERROR;
  }
  rekeying_state =
      (rekeying_state == OnlyZero) ? SwitchingToOne : SwitchingToZero;
  return RTP_OK;
}

rtp_error_t uvgrtp::srtp::rekey_disable_old_remote_srtp_ctx() {
  if (!(rce_flags_ & RCE_RECEIVE_ONLY)) {
    UVG_LOG_ERROR("rekey_disable_old_remote_srtp_ctx must only be called on "
                  "receiving streams!");
    return RTP_GENERIC_ERROR;
  }
  if (rekeying_state != SwitchingToZero && rekeying_state != SwitchingToOne) {
    UVG_LOG_ERROR(
        "Can not disable old SRTP context as only one is currently active.");
    return RTP_GENERIC_ERROR;
  }
  if (rekeying_state == SwitchingToZero) {
    rekeying_state = OnlyZero;
    clear_replay_list(One);
  } else if (rekeying_state == SwitchingToOne) {
    rekeying_state = OnlyOne;
    clear_replay_list(Zero);
  }
  return RTP_OK;
}

rtp_error_t uvgrtp::srtp::rekey_replace_local_srtp_ctx(uint8_t *key,
                                                       uint8_t *salt) {
  if (!(rce_flags_ & RCE_SRTP_KMNGMNT_USER)) {
    UVG_LOG_ERROR(
        "Rekeying is only supported with RCE_SRTP_KMNGMNT_USER flag.");
    return RTP_NOT_SUPPORTED;
  }
  if (!(rce_flags_ & RCE_SEND_ONLY)) {
    UVG_LOG_ERROR("rekey_switch_remote_srtp_ctx must only be called on "
                  "receiving streams!");
    return RTP_GENERIC_ERROR;
  }
  cleanup_context(*local_srtp_ctx_);
  if (init_srtp_context(*local_srtp_ctx_, type_, rce_flags_, key, salt) !=
      RTP_OK) {
    UVG_LOG_ERROR("Error initializing new SRTP context");
    return RTP_GENERIC_ERROR;
  }
  return RTP_OK;
}

rtp_error_t uvgrtp::srtp::encrypt(uint32_t ssrc, uint16_t seq, uint8_t *buffer,
                                  size_t len) {
  if (use_null_cipher_)
    return RTP_OK;

  uint8_t iv[UVG_IV_LENGTH] = {0};
  uint64_t index = (((uint64_t)local_srtp_ctx_->roc) << 16) + seq;

  // Sequence number has wrapped around, update rollover Counter
  if (seq == 0xffff) {
    local_srtp_ctx_->roc++;
    UVG_LOG_DEBUG("SRTP encryption rollover, rollovers so far: %lu",
                  local_srtp_ctx_->roc);
  }

  if (create_iv(iv, ssrc, index, local_srtp_ctx_->salt_key) != RTP_OK) {
    UVG_LOG_ERROR("Failed to create IV, unable to encrypt the RTP packet!");
    return RTP_INVALID_VALUE;
  }

  uvgrtp::crypto::aes::ctr ctr(local_srtp_ctx_->enc_key, local_srtp_ctx_->n_e,
                               iv);
  ctr.encrypt(buffer, buffer, len);

  return RTP_OK;
}

void compute_hmac(const uint8_t *buffer, size_t len,
                  const uvgrtp::srtp_ctx_t &srtp, uint8_t *out_digest) {
  auto hmac_sha1 =
      uvgrtp::crypto::hmac::sha1(srtp.auth_key, UVG_AES_KEY_LENGTH);

  hmac_sha1.update(buffer, len - UVG_AUTH_TAG_LENGTH);
  hmac_sha1.update((uint8_t *)&srtp.roc, sizeof(srtp.roc));
  hmac_sha1.final(out_digest, UVG_AUTH_TAG_LENGTH);
}

rtp_error_t uvgrtp::srtp::recv_packet_handler(void *args, int rce_flags,
                                              uint8_t *read_ptr, size_t size,
                                              uvgrtp::frame::rtp_frame **out) {
  (void)rce_flags;
  (void)read_ptr;
  (void)size;

  auto srtp = (uvgrtp::srtp *)args;
  auto frame = *out;
  which_srtp_ctx which_srtp = Zero;

  if (frame->dgram_size < RTP_HDR_SIZE ||
      (srtp->authenticate_rtp() &&
       frame->dgram_size < RTP_HDR_SIZE + UVG_AUTH_TAG_LENGTH)) {
    UVG_LOG_ERROR("Received SRTP packet that has too small size");
    return RTP_GENERIC_ERROR;
  }

  /* Calculate authentication tag for the packet and compare it against the one
   * we received */
  if (srtp->authenticate_rtp()) {
    uint8_t digest[10] = {0};
    bool verified = false;
    if (rekeying_state == OnlyZero || rekeying_state == SwitchingToZero ||
        rekeying_state == SwitchingToOne) {
      compute_hmac(frame->dgram, frame->dgram_size, remote_srtp_ctxs_[0],
                   digest);
      verified = !memcmp(digest,
                         &frame->dgram[frame->dgram_size - UVG_AUTH_TAG_LENGTH],
                         UVG_AUTH_TAG_LENGTH);
      if (verified) {
        which_srtp = Zero;
      }
    }
    if (!verified &&
        (rekeying_state == OnlyOne || rekeying_state == SwitchingToZero ||
         rekeying_state == SwitchingToOne)) {
      compute_hmac(frame->dgram, frame->dgram_size, remote_srtp_ctxs_[1],
                   digest);
      verified = !memcmp(digest,
                         &frame->dgram[frame->dgram_size - UVG_AUTH_TAG_LENGTH],
                         UVG_AUTH_TAG_LENGTH);
      if (verified) {
        which_srtp = One;
      }
    }
    if (!verified) {
      UVG_LOG_ERROR("Authentication tag mismatch!");
      return RTP_GENERIC_ERROR;
    }
    if (srtp->is_replayed_packet(digest, which_srtp)) {
      UVG_LOG_ERROR("Replayed packet received, discarding!");
      return RTP_GENERIC_ERROR;
    }
    frame->payload_len -= UVG_AUTH_TAG_LENGTH;
  }

  if (srtp->use_null_cipher())
    return RTP_PKT_NOT_HANDLED;

  uint16_t seq = frame->header.seq;
  uint32_t ssrc = frame->header.ssrc;
  uint32_t ts = frame->header.timestamp;
  uint64_t index = 0;

  auto &remote_ctx = srtp->get_remote_ctxs()[which_srtp == Zero ? 0 : 1];

  /* as the sequence number approaches 0xffff and is close to wrapping around,
   * special care must be taken to use correct rollover counter as it's
   * possible that packets come out of order around this overflow boundary
   * and if e.g. we first receive packet with sequence number 0xffff and thus
   * update ROC to ROC + 1 and after that we receive packet with sequence number
   * 0xfffe, we use an incorrect value for ROC as the the packet 0xfffe was
   * encrypted with ROC - 1.
   *
   * It is a reasonable assumption that correct ROC differs from "ctx->roc" at
   * most by 1 (-, +) because if the difference is more than 1, the input frame
   * would be larger than 90 MB.
   *
   * Here the assumption is that the offset for an incorrectly ordered packet is
   * at most 10k packets*/
  if (ts == remote_ctx.rts && (uint16_t)(seq + MAX_OFF) < MAX_OFF) {
    index = (((uint64_t)remote_ctx.roc - 1) << 16) + seq;
  } else {
    index = (((uint64_t)remote_ctx.roc) << 16) + seq;
  }

  /* Sequence number has wrapped around, update rollover Counter */
  if (seq == 0xffff) {
    remote_ctx.roc++;
    remote_ctx.rts = ts;
    UVG_LOG_DEBUG("SRTP decryption rollover, rollovers so far: %lu",
                  remote_ctx.roc);
  }

  uint8_t iv[UVG_IV_LENGTH] = {0};
  if (srtp->create_iv(iv, ssrc, index, remote_ctx.salt_key) != RTP_OK) {
    UVG_LOG_ERROR("Failed to create IV, unable to encrypt the RTP packet!");
    return RTP_GENERIC_ERROR;
  }

  uvgrtp::crypto::aes::ctr ctr(remote_ctx.enc_key, remote_ctx.n_e, iv);
  ctr.decrypt(frame->payload, frame->payload, frame->payload_len);

  return RTP_PKT_MODIFIED;
}

rtp_error_t uvgrtp::srtp::send_packet_handler(void *arg,
                                              uvgrtp::buf_vec &buffers) {
  auto srtp = (uvgrtp::srtp *)arg;
  auto frame = (uvgrtp::frame::rtp_frame *)buffers.at(0).second;
  auto local_ctx = srtp->get_local_ctx();
  auto off = srtp->authenticate_rtp() ? 2 : 1;
  auto data = buffers.at(buffers.size() - off);
  auto hmac_sha1 =
      uvgrtp::crypto::hmac::sha1(local_ctx->auth_key, UVG_AUTH_LENGTH);
  rtp_error_t ret = RTP_OK;

  if (srtp->use_null_cipher())
    goto authenticate;

  ret = srtp->encrypt(ntohl(frame->header.ssrc), ntohs(frame->header.seq),
                      data.second, data.first);

  if (ret != RTP_OK) {
    UVG_LOG_ERROR("Failed to encrypt RTP packet!");
    return ret;
  }

authenticate:
  if (!srtp->authenticate_rtp())
    return RTP_OK;

  for (size_t i = 0; i < buffers.size() - 1; ++i)
    hmac_sha1.update((uint8_t *)buffers[i].second, buffers[i].first);

  hmac_sha1.update((uint8_t *)&local_ctx->roc, sizeof(local_ctx->roc));
  hmac_sha1.final((uint8_t *)buffers[buffers.size() - 1].second,
                  UVG_AUTH_TAG_LENGTH);

  return ret;
}

bool uvgrtp::srtp::authenticate_rtp() const { return authenticate_rtp_; }
