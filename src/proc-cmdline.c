/* SPDX-License-Identifier: LGPL-2.1+ */

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "fileio.h"
#include "macro.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "string-util.h"
#include "util.h"
#include "virt.h"

int proc_cmdline(char **ret) {
        assert(ret);

        if (detect_container() > 0)
                return get_process_cmdline(1, 0, false, ret);
        else
                return read_one_line_file("/proc/cmdline", ret);
}

int parse_proc_cmdline(int (*parse_item)(const char *key, const char *value)) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        int r;

        assert(parse_item);

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *value = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Filter out arguments that are intended only for the
                 * initrd */
                if (!in_initrd() && startswith(word, "rd."))
                        continue;

                value = strchr(word, '=');
                if (value)
                        *(value++) = 0;

                r = parse_item(word, value);
                if (r < 0)
                        return r;
        }

        return 0;
}
