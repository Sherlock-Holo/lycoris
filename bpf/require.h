//
// Created by sherlock on 22-7-3.
//

#ifndef BPF_LEARN_REQUIRE_H
#define BPF_LEARN_REQUIRE_H

// fix require stub-32.sh problem
#ifndef __x86_64__
#define __x86_64__ 1
#endif
#ifndef __LP64__
#define __LP64__ 1
#endif

#include <sys/socket.h>

#endif //BPF_LEARN_REQUIRE_H
