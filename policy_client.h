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

#ifndef POLICY_CLIENT_H
#define POLICY_CLIENT_H

#include "policy_global.h"

/**
 * Fills in the designated policy_req struct with the given fields;
 * this interface should change as the fields inside of policy_req
 * change. The lengths of the process and destination server names
 * must be less than POLICYD_STRING_SIZE.
 * After calling this function, the app should be able to send the
 * filled-in policy_req to policyd via the requestPolicyDecision()
 * function.
 * Returns: size of policy_req on success, negative on error.
 */
int construct_policy_req(policy_req *msg, const char *process_name,
        const char *dest_name, int taint_tag);

/**
 * Sends the policy_req to the policyd, which should be connected on
 * the given fd, and stores the response in the given policy_resp.
 * Returns: 0 on success, negative on error. On success, the policy_resp
 *   is filled. If an error is returned, the caller should close the
 *   socket.
 */
int request_policy_decision(int sockfd, policy_req *request,
        policy_resp *response);

#endif
