/*
 * Copyright (C) 2008 The Android Open Source Project
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
#include <cutils/sockets.h>
#include "policy_global.h"

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policy_client"
#endif

/**
 * Fills in the designated policy_req struct with the given fields.
 * Returns: size of policy_req on success, negative on error.
 */
int construct_policy_req(policy_req *msg, const char *process_name,
                const char *dest_name, int taint_tag) {
    LOGW("phornyac: construct_policy_req: entered");
    if (strlen(process_name) >= POLICYD_STRING_SIZE) {
        LOGW("phornyac: construct_policy_req: processName too long, "
                "returning -1");
        return -1;
    }
    if (strlen(dest_name) >= POLICYD_STRING_SIZE) {
        LOGW("phornyac: construct_policy_req: destName too long, "
                "returning -1");
        return -1;
    }

    /* Some of these fields are currently unused */
    msg->request_code = -1;
    strncpy(msg->process_name, process_name, POLICYD_STRING_SIZE-1);
    msg->process_name[POLICYD_STRING_SIZE-1] = '\0';
    strncpy(msg->dest_name, dest_name, POLICYD_STRING_SIZE-1);
    msg->dest_name[POLICYD_STRING_SIZE-1] = '\0';
    msg->taint_tag = taint_tag;
    msg->app_status = -1;

    LOGW("phornyac: construct_policy_req: returning sizeof(policy_req) "
            "(%d)", sizeof(policy_req));
    return (sizeof(policy_req));
}

int request_policy_decision(int sockfd, policy_req *request,
        policy_resp *response) {
    int ret;
    LOGW("phornyac: request_policy_decision: entered");

    LOGW("phornyac: request_policy_decision: calling send_policy_req() "
            "with sockfd=%d", sockfd);
    ret = send_policy_req(sockfd, request);
    if (ret < 0) {
        LOGW("phornyac: request_policy_decision: send_policy_req() "
                "returned error=%d", ret);
        LOGW("phornyac: request_policy_decision: returning -1");
        return -1;
    }

    LOGW("phornyac: request_policy_decision: send_policy_req() succeeded, "
            "calling recv_policy_resp()");
    ret = recv_policy_resp(sockfd, response);
    if (ret < 0) {
        LOGW("phornyac: request_policy_decision: recv_policy_resp() "
                "returned error=%d", ret);
        LOGW("phornyac: request_policy_decision: returning -1");
        return -1;
    }
    LOGW("phornyac: request_policy_decision: recv_policy_resp() succeeded, "
            "printing response");
    print_policy_resp(response);

    LOGW("phornyac: request_policy_decision: returning 0");
    return 0;

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
}

