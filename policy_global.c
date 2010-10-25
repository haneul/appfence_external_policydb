/*
 * Copyright (C) 2007 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <utils/Log.h>
#include <sys/types.h>
#include <sys/socket.h>
#include "policy_global.h"

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policy_global"
#endif

int send_policy_req(int sockfd, policy_req *msg) {
    int size, flags, ret;

    LOGW("phornyac: send_policy_req: entered");

    size = sizeof(*msg);
    flags = 0;  /* See send(2) */
    LOGW("phornyac: send_policy_req: calling send() of size %d to fd %d "
            "with flags=0x%X", size, sockfd, flags);
    ret = send(sockfd, msg, size, flags);
    if (ret < 0) {
        LOGW("phornyac: send_policy_req: error number: %d (EPIPE=%d)",
                errno, EPIPE);
        LOGW("phornyac: send_policy_req: send() returned error, "
                "returning -1");
        return -1;
    }
    if (ret != size) {
        LOGW("phornyac: send_policy_req: error number: %d", errno);
        LOGW("phornyac: send_policy_req: send() did not complete, "
                "only wrote %d of %d bytes", ret, size);
        LOGW("phornyac: send_policy_req: returning -1");
        return -1;
    }
    LOGW("phornyac: send_policy_req: send() returned success, "
            "returning 0");
    return 0;
}

int recv_policy_req(int sockfd, policy_req *msg) {
    int size, flags, ret;

    LOGW("phornyac: recv_policy_req: entered");

    size = sizeof(*msg);
    flags = MSG_WAITALL;  /* Block until the FULL message received */
    LOGW("phornyac: recv_policy_req: calling recv() of size %d from fd %d "
            "with flags=0x%X", size, sockfd, flags);
    ret = recv(sockfd, msg, size, flags);
    if (ret < 0) {
        LOGW("phornyac: recv_policy_req: error number: %d", errno);
        LOGW("phornyac: recv_policy_req: recv() returned error, "
                "returning -1");
        return -1;
    }
    if (ret == 0) {
        LOGW("phornyac: recv_policy_req: recv() returned 0, meaning "
                "server has performed orderly shutdown on socket");
        LOGW("phornyac: recv_policy_req: returning 0");
        return 1;
    }
    if (ret != size) {
        LOGW("phornyac: recv_policy_req: error number: %d", errno);
        LOGW("phornyac: recv_policy_req: recv() did not complete, "
                "only got %d of %d bytes", ret, size);
        LOGW("phornyac: recv_policy_req: returning -1");
        return -1;
    }
    LOGW("phornyac: recv_policy_req: recv() returned success, "
            "returning 0");
    return 0;
#if 0
            //bytes_read = 0;
            //msg_size = sizeof(msg_read);
            //buf = (char *)&msg_read;
            //read_ret = -1;
            ////while ((bytes_read < msg_size) && (read_ret != 0)) {
            //while (0) {  /* test code */
            //    LOGW("phornyac: allowExposeNetworkImpl(): calling read() "
            //            "on policy_sockfd, msg_size=%d, bytes_read=%d",
            //            msg_size, bytes_read);
            //    read_ret = read(policy_sockfd, buf, msg_size);
            //    if (read_ret < 0) {
            //        LOGW("phornyac: allowExposeNetworkImpl(): read() "
            //                "returned read_ret=%d, doing nothing", read_ret);
            //        break;  /* exit while loop */
            //    }
            //    LOGW("phornyac: allowExposeNetworkImpl(): read() "
            //            "returned %d bytes read", read_ret);
            //    bytes_read += read_ret;
            //    buf += read_ret;
            //}
            ////LOGW("phornyac: allowExposeNetworkImpl(): "
            ////        "msg_read contents: %s", msg_read.msg);
#endif
}

int send_policy_resp(int sockfd, policy_resp *msg) {
    int size, flags, ret;

    LOGW("phornyac: send_policy_resp: entered");

    size = sizeof(*msg);
    flags = 0;  /* See send(2) */
    LOGW("phornyac: send_policy_resp: calling send() of size %d to fd %d "
            "with flags=0x%X", size, sockfd, flags);
    ret = send(sockfd, msg, size, flags);
    if (ret < 0) {
        LOGW("phornyac: send_policy_resp: error number: %d (EPIPE=%d)",
                errno, EPIPE);
        LOGW("phornyac: send_policy_resp: send() returned error, "
                "returning -1");
        return -1;
    }
    if (ret != size) {
        LOGW("phornyac: send_policy_resp: error number: %d", errno);
        LOGW("phornyac: send_policy_resp: send() did not complete, "
                "only wrote %d of %d bytes", ret, size);
        LOGW("phornyac: send_policy_resp: returning -1");
        return -1;
    }
    LOGW("phornyac: send_policy_resp: send() returned success, "
            "returning 0");
    return 0;
}

int recv_policy_resp(int sockfd, policy_resp *msg) {
    int size, flags, ret;

    LOGW("phornyac: recv_policy_resp: entered");

    size = sizeof(*msg);
    flags = MSG_WAITALL;  /* Block until the FULL message received */
    LOGW("phornyac: recv_policy_resp: calling recv() of size %d from fd %d "
            "with flags=0x%X", size, sockfd, flags);
    ret = recv(sockfd, msg, size, flags);
    if (ret < 0) {
        LOGW("phornyac: recv_policy_resp: error number: %d", errno);
        LOGW("phornyac: recv_policy_resp: recv() returned error, "
                "returning -1");
        return -1;
    }
    if (ret == 0) {
        LOGW("phornyac: recv_policy_resp: recv() returned 0, meaning "
                "server has performed orderly shutdown on socket");
        LOGW("phornyac: recv_policy_resp: returning 0");
        return 1;
    }
    if (ret != size) {
        LOGW("phornyac: recv_policy_resp: error number: %d", errno);
        LOGW("phornyac: recv_policy_resp: recv() did not complete, "
                "only got %d of %d bytes", ret, size);
        LOGW("phornyac: recv_policy_resp: returning -1");
        return -1;
    }
    LOGW("phornyac: recv_policy_resp: recv() returned success, "
            "returning 0");
    return 0;
}

void print_policy_req(policy_req *msg) {
    LOGW("phornyac: print_policy_req: request_code=%d, process_name=%s, "
            "dest_name=%s, taint_tag=0x%X, app_status=%d",
            msg->request_code, msg->process_name, msg->dest_name,
            msg->taint_tag, msg->app_status);
}

void print_policy_resp(policy_resp *msg) {
    LOGW("phornyac: print_policy_resp: response_code=%d",
            msg->response_code);
}

