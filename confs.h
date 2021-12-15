#ifndef CONFS_H
#define CONFS_H

#include <dirent.h>
#include <sys/types.h>

#define CLAMONE_MAJOR 1
#define CLAMONE_MINOR 0
#define CLAMONE_BUILD 0
#define CLAMONE_VERSION "1.0.2"
#define CLAMONE_VERSION_L QT_VERSION_CHECK(CLAMONE_MAJOR, CLAMONE_MINOR, CLAMONE_BUILD)

#define DELTA_DAY 60*60*24
#define DELTA_WEEK DELTA_DAY*7
#define DELTA_MONTH DELTA_DAY*30
#define DELTA_YEAR DELTA_DAY*365

#define DELTA_BASE DELTA_WEEK

#ifdef _WIN32
#define PATHSEP "\\"
#else
#define PATHSEP "/"
#endif

#ifndef _WIN32
#define LINE_END QByteArray end("\n", 1);
#else
#define LINE_END QByteArray end("\r\n", 2);
#endif

enum ClamOneMainStackOrder {
    Scan = 0,
    Schedule = 1,
    Status = 2,
    Quarantine = 3,
    Log = 4,
    Messages = 5,
    Update = 6,
    Graphs = 7,
    Setup = 8,
    Help = 9
};

enum ClamOneScanStackOrder {
    Error = 0,
    Quick = 1,
    Deep = 2,
    Running = 3
};

enum ClamOneEventsStackOrder {
    EventGeneral = 0,
    EventFound = 1,
    EventQuarantine = 2
};

enum ClamOneConfigStackOrder {
    ConfigBasic = 0,
    ConfigClamdconf = 1,
    ConfigFreshclamconf = 2
};

#define CLAMONE_UNKNOWN (0)
#define CLAMONE_OK (1<<0)
#define CLAMONE_WARN (1<<1)
#define CLAMONE_CAUTION (1<<2)
#define CLAMONE_ERROR (1<<3)

//#define CLAMONE_DEBUG

#endif // CONFS_H
