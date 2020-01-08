#pragma once

#include <map>
#include "conn.hh"
#include "reader.hh"
#include "writer.hh"

namespace kvz_rtp {

    
    class context {
        public:
            context(rtp_ctx_flags_t flags);
            ~context();

            /* Add configuration for a flag. Examples could be:
             *
             * rtp_ctx.configure(RTP_CTX_CONF_PROBATION_ZONE_SIZE, 10);
             * rtp_ctx.configure(RTP_CTX_CONF_MAX_QUEUED_MSGS,     50); 
             *
             * The first one sets the probation zone size to 10 packets and the second 
             * sets the maximum size of transaction queueu to 50 transactions */
            void configure(rtp_ctx_conf_flags_t flag, ssize_t value);

            /* Start listening to incoming RTP packets form src_addr:src_port
             *
             * Read packets are stored in a ring buffer which can be read by
             * calling kvz_rtp::reader::pull_frame() */
            kvz_rtp::reader *create_reader(std::string src_addr, int src_port, rtp_format_t fmt);

            /* Open connection for writing RTP packets to dst_addr:dst_port
             *
             * Packets can be sent by calling kvz_rtp::writer::push_frame() */
            kvz_rtp::writer *create_writer(std::string dst_addr, int dst_port, rtp_format_t fmt);
            kvz_rtp::writer *create_writer(std::string dst_addr, int dst_port, int src_port, rtp_format_t fmt);

            /* call reader/writer-specific destroy functions, send an RTCP BYE message
             * and remove the connection from conns_ map */
            rtp_error_t destroy_writer(kvz_rtp::writer *writer);
            rtp_error_t destroy_reader(kvz_rtp::reader *reader);

            std::string& get_cname();

        private:
            kvz_rtp::writer *create_writer(std::string dst_addr, int dst_port);

            /* Generate CNAME for participant using host and login names */
            std::string generate_cname();

            /* CNAME is the same for all connections */
            std::string cname_;

            /* RTP context configuration, holds both writer and reader configurations 
             * that are passed to those objects when they're created  */
            rtp_ctx_conf_t ctx_conf_;

            std::map<uint32_t, connection *> conns_;
        };
};
