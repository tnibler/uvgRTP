#include <uvgrtp/lib.hh>
#include <uvgrtp/clock.hh>
#include <cstring>
#include <algorithm>

extern void *get_mem(int argc, char **argv, size_t& len);

std::chrono::high_resolution_clock::time_point fpts, fpte;
size_t nframes = 0;

void hook_sender(void *arg, uvg_rtp::frame::rtp_frame *frame)
{
    (void)arg, (void)frame;

    if (frame)
        fpte = std::chrono::high_resolution_clock::now();
}

void hook_receiver(void *arg, uvg_rtp::frame::rtp_frame *frame)
{
    auto hevc = (uvg_rtp::media_stream *)arg;
    hevc->push_frame(frame->payload, frame->payload_len, 0);
    nframes++;
}

int receiver(char *ip)
{
    uvg_rtp::context rtp_ctx;
    std::string addr(ip);

    auto sess = rtp_ctx.create_session(addr);
    auto hevc = sess->create_stream(
        8889,
        8888,
        RTP_FORMAT_HEVC,
        RCE_SYSTEM_CALL_DISPATCHER
    );

    hevc->install_receive_hook(hevc, hook_receiver);

    while (nframes != 602)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

    return 0;
}

int sender(char *ip)
{
    size_t len      = 0;
    void *mem       = get_mem(0, NULL, len);
    uint64_t csize  = 0;
    uint64_t diff   = 0;
    size_t frames   = 0;
    size_t total    = 0;
    rtp_error_t ret = RTP_OK;
    std::string addr(ip);

    uvg_rtp::context rtp_ctx;

    auto sess = rtp_ctx.create_session(addr);
    auto hevc = sess->create_stream(
        8888,
        8889,
        RTP_FORMAT_HEVC,
        RCE_SYSTEM_CALL_DISPATCHER
    );

    hevc->install_receive_hook(nullptr, hook_sender);

    for (size_t offset = 0; offset < len; ++frames) {
        memcpy(&csize, (uint8_t *)mem + offset, sizeof(uint64_t));

        offset += sizeof(uint64_t);

        fpts = std::chrono::high_resolution_clock::now();

        if ((ret = hevc->push_frame((uint8_t *)mem + offset, csize, 0)) != RTP_OK) {
            fprintf(stderr, "push_frame() failed!\n");
            for (;;);
        }

        /* because the input frame might be split into multiple separate frames, we should
         * calculate the latency using the timestamp before push and after the last received frame.
         *
         * Sleep for 5 seconds before calculating the latency to prevent us from reading the frame
         * receive time too early (NOTE: this does not affect the latency calculations at all) */
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));

        diff = std::chrono::duration_cast<std::chrono::microseconds>(fpte - fpts).count();

        /* If the difference is more than 10 seconds, it's very likely that the frame was dropped
         * and this latency value is bogus and should be discarded */
        if (diff >= 10 * 1000 * 1000)
            frames--;
        else
            total += diff;

        offset += csize;
    }
    rtp_ctx.destroy_session(sess);

    fprintf(stderr, "avg latency: %lf\n", total / (float)frames);

    return 0;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: ./%s <send|recv> <ip>\n", __FILE__);
        exit(EXIT_FAILURE);
    }

    return !strcmp(argv[1], "sender") ? sender(argv[2]) : receiver(argv[2]);
}
