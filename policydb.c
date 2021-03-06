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

#include "policydb.h"
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>
#include <libxml/xmlreader.h>
#include <cutils/log.h>
#include <policy_global.h>

/* Enable this to run some debugging code. The debugging code should have no
 * side-effects at all anyway though. */
#define TESTCODE

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "policydb"
#endif

/**
 * From dalvik/vm/Common.h:
 * The <stdbool.h> definition uses _Bool, a type known to the compiler.
 */
#ifdef HAVE_STDBOOL_H
# include <stdbool.h>   /* C99 */
#else
# ifndef __bool_true_false_are_defined
  typedef enum { false=0, true=!false } bool;
# define __bool_true_false_are_defined 1
# endif
#endif

/* Set to true to use character hostnames, rather than numerical
 * IP addresses, for matching the policy entries. */
static bool USE_HOSTNAME = true;

/**
 * Persistent variables for storing SQLite database connection, etc.
 */
const char *db_file = "/data/data/com.android.settings/policydb.db";
  /* Looks like this after sqlite3_open():
   * -rw-r--r-- root     root         3072 2010-11-14 23:07 policy.db */
sqlite3 *db_ptr = NULL;

/**
 * These constants define table structure/columns; all of the dbXyzs
 * should match each other!! (It's too damn hard to dynamically
 * construct the create table string, etc. in C). ALSO, these should
 * match what's used in the XML file!!!
 * Used by create_db_table() to create the database table.
 */
const char *db_tablename = "policy";
enum dbCols {    //must start at 0 for indexing into database!
    SOURCE = 0,     //SQLITE_TEXT
    DEST,       //SQLITE_TEXT
    TAINT,      //SQLITE_INTEGER
    COLUMNS         //must always be last!!!
};
const char *db_col_names[] = {
    "source",
    "dest",
    "taint",
};
const char *db_col_types[] = {
    "TEXT",
    "TEXT",
    "INTEGER",
};
const char *db_createstring =
    "CREATE TABLE policy (src TEXT, dest TEXT, taint INTEGER)";
      //make sure string after TABLE is db_tablename
const char *db_dropstring =
    "DROP TABLE policy";
      //make sure string after TABLE is db_tablename
/* For now, we expect our depth 0 "root" XML nodes to always be named this: */
const char *root_name = "rule";


/**
 * Constructs a query string that gets the records/rows of the database matching
 * the given source application name. Returns pointer to a newly-allocated string
 * (which should be freed by the caller) on success, or returns NULL on failure.
 */
char *construct_query_string(const char *source) {
    int queryLen;
    char *queryString;
    const char *select = "SELECT";
    const char *columns = "*";
    const char *from = "FROM";
    const char *where = "WHERE";
 
    //LOGW("phornyac: construct_query_string(): entered");
    /**
     * Construct the SQL query string:
     *   SELECT *
     *     FROM <table_name>
     *     WHERE src='<source>'
     * Wildcards: ??
     * Impt: taint may not match exactly!
     *   So, use the callback function for each gotten record to AND the taint
     *   from the database record with the current data taint! This means that
     *   we will "match" if any bit in current data taint tag matches any bit in
     *   taint tag stored in database.
     *     Do this for destination too???? Yes!
     *       So, just WHERE on the source!
     * http://www.w3schools.com/sql/sql_select.asp
     * http://www.w3schools.com/sql/sql_where.asp
     *   Use single quotes, i.e. SELECT * FROM Persons WHERE FirstName='Tove'
     * http://www.w3schools.com/sql/sql_and_or.asp
     */

    //XXX: should sanitize input to this function, or risk SQL injection attack!

    /**
     * Examples: http://www.sqlite.org/lang_expr.html
     *   SELECT * FROM policy WHERE src='com.android.browser'
     *     Get rows for source app com.android.browser
     *   SELECT * FROM policy WHERE src LIKE '%'
     *     Get all rows
     *   SELECT * FROM policy WHERE src='com.android.browser' OR src='*'
     *     Get rows for source app com.android.browser and for global policy
     *     that applies to all source apps
     */
    queryLen = strlen(select) + strlen(" ") + strlen(columns) + 
        strlen(" ") + strlen(from) +
        strlen(" ") + strlen(db_tablename) + strlen(" ") + strlen(where) +
        strlen(" src=\'") + strlen(source) + strlen("\' OR src=\'*\'") + 1;
    queryString = (char *)malloc(queryLen * sizeof(char));
    snprintf(queryString, queryLen, "%s %s %s %s %s src=\'%s\' OR src=\'*\'",
            select, columns, from, db_tablename, where, source);
    //LOGW("phornyac: construct_query_string(): queryLen=%d, queryString=%s",
    //        queryLen, queryString);
    return queryString;
}

/* Prints the current database row. */
void print_row(sqlite3_stmt *stmt){
    const unsigned char *dbSrc;
    const unsigned char *dbDest;
    int dbTaint;

    /**
     * Get the values from the destination and taint tag columns:
     * http://sqlite.org/c3ref/column_blob.html
     */
    dbSrc = sqlite3_column_text(stmt, SOURCE);
    dbDest = sqlite3_column_text(stmt, DEST);
    dbTaint = sqlite3_column_int(stmt, TAINT);
 
    LOGW("phornyac: print_row(): dbSrc=%s, dbDest=%s, dbTaint=0x%X",
            dbSrc, dbDest, dbTaint);
}

/**
 * Returns true if the two destination IP addresses match, or if the
 * destination stored in the database row is the wildcard "*".
 * XXX: enhance this function to consider subnets, partial IP addresses /
 *   hostnames, etc.!
 */
bool destination_match(const char *curDest, const char *dbDest) {
    LOGW("phornyac: destination_match: curDest=%s, dbDest=%s",
            curDest, dbDest);
    
    if ((strcmp("*", dbDest) == 0) || (strcmp(curDest, dbDest) == 0)) {
        LOGW("phornyac: destination_match: returning true");
        return true;
    }
    //LOGW("phornyac: destination_match: returning false");
    return false;
}

/**
 * Returns true if the two destination hostnames match, or if the
 * destination stored in the database row is the wildcard "*". A
 * destination hostname matches the database (exposure policy)
 * hostname if the db hostname is a substring of the destination
 * hostname (case-insensitive). If the destination hostname is
 * NULL, then this does not count as a match.
 */
bool hostname_match(const char *curDest, const char *dbDest) {
    LOGW("phornyac: hostname_match: curDest=%s, dbDest=%s",
            curDest, dbDest);
    if (curDest == NULL)
        return false;

    /* strcasestr() returns pointer to first occurrence of arg2 in 
     * arg1, or NULL if not found. */
    if ((strcmp("*", dbDest) == 0) ||
        (strcasestr(curDest, dbDest) != NULL)) {
        LOGW("phornyac: hostname_match: returning true");
        return true;
    }
    return false;
}

/**
 * Returns true if the two taint tags "match," i.e. if they have any of the same
 * bits set.
 *
 * User either cares about specific taint (in which case he'll
 * specify that taint in XML file), cares about ALL taint (in which case
 * he'll use (2^32)-1 (4294967295) in the XML file), or doesn't
 * care about taint (in which case he'll specify 0, which means
 * we want to match this rule no matter what the current taint
 * is). So, we count "0" as the wildcard for taint, which is convenient,
 * because if "*" is specified for the taint rule in the XML file,
 * it becomes 0 when sqlite stores it in the database as an integer.
 */
bool taint_match(int curTaint, int dbTaint) {
    LOGW("phornyac: taint_match: curTaint=0x%X, dbTaint=0x%X",
            curTaint, dbTaint);
    if ((dbTaint == 0) || (curTaint & dbTaint)) {
        LOGW("phornyac: taint_match: returning true");
        return true;
    }
    LOGW("phornyac: taint_match: returning false");
    return false;
}

/**
 * Function that is called for every database record that our query
 * returns. If we select the records based solely on the application name,
 * then this function should return true if the destination server and taint
 * of the data about to be transmitted BOTH match one of the records.
 */
bool check_row_for_match(sqlite3_stmt *db_row, const char *process_name, 
        const char *dest, int taint) {
    const unsigned char *dbDest;
    int dbTaint;
    bool match = false;

    //LOGW("phornyac: check_row_for_match(): entered");

    /**
     * Get the values from the destination and taint tag columns:
     * http://sqlite.org/c3ref/column_blob.html
     */
    dbDest = sqlite3_column_text(db_row, DEST);
    if (dbDest == NULL) {
        LOGW("phornyac: check_row_for_match(): dbDest got NULL, returning false!");
        return false;
    }
    dbTaint = sqlite3_column_int(db_row, TAINT);

    /* Return true if BOTH the destinations and the taints match: */
    if (USE_HOSTNAME) {
        match = (hostname_match(dest, (const char *)dbDest) &&
                 taint_match(taint, dbTaint));
    } else {
        match = (destination_match(dest, (const char *)dbDest) &&
                 taint_match(taint, dbTaint));
    }
    if (match) {
        LOGW("phornyac: check_row_for_match: MATCHED process_name=[%s], "
                "hostname=[%s], db_name=[%s], taint-tag=[0x%X]",
                process_name, dest, dbDest, taint);
    } else {
        //This will cause pretty heavy logging:
        LOGW("phornyac: check_row_for_match: no-match process_name=[%s], "
                "hostname=[%s], db_name=[%s], taint-tag=[0x%X]",
                process_name, dest, dbDest, taint);
    }
    return match;
}

/**
 * Adds the given (source, dest, taint) triple to the database table.
 * None of the inputs should be NULL!
 * Returns 0 on success, negative on error.
 */
int insert_row(sqlite3 *db, const char *tableName, const char *source,
        const char *dest, const char *taint) {
    sqlite3_stmt *insertStmt;
    int len;
    int err;
    char *insertString;

    LOGW("phornyac: insert_row(): entered");
    //(DEBUG: Get all rows in a table: SELECT * FROM Persons)

    if (!source || !dest || !taint) {
        LOGW("phornyac: insert_row(): one of source||dest||taint is NULL, "
                "returning -1");
        return -1;
    }

    /**
     * Construct the INSERT string:
     *   INSERT INTO table_name VALUES (source, dest, taint)
     * See http://www.w3schools.com/sql/sql_insert.asp
     * XXX: not safe from injection attack???
     */
    const char *insertInto = "INSERT INTO";
    const char *values = "VALUES";
    len = strlen(insertInto) + strlen(" ") + strlen(tableName) + 
        strlen(" ") + strlen(values) + strlen(" (\'") + strlen(source) +
        strlen("\', \'") + strlen(dest) + strlen("\', \'") + strlen(taint) +
        strlen("\')") + 1;
    insertString = malloc(len * sizeof(char));
    /* Must use quotes around column values inside () ! */
    snprintf(insertString, len, "%s %s %s (\'%s\', \'%s\', \'%s\')",
            insertInto, tableName, values, source, dest, taint);
    LOGW("phornyac: insert_row(): constructed insertString=%s", insertString);

    /**
     * Prepare an SQLite statement with the INSERT string:
     * See http://sqlite.org/c3ref/prepare.html
     */
    LOGW("phornyac: insert_row(): calling sqlite3_prepare_v2()");
    err = sqlite3_prepare_v2(db, insertString, len, &insertStmt, NULL);
    free(insertString);
    if (err != SQLITE_OK) {
        LOGW("phornyac: insert_row(): sqlite3_prepare_v2() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insert_row(): returning -1 due to errors");
        return -1;
    }

    /**
     * Execute the prepared statement:
     */
    LOGW("phornyac: insert_row(): calling sqlite3_step() to execute "
            "INSERT statement");
    err = sqlite3_step(insertStmt);
    if (err != SQLITE_DONE) {
        LOGW("phornyac: insert_row(): sqlite3_step() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insert_row(): returning -1 due to errors");
        sqlite3_finalize(insertStmt);  //ignore return value
        return -1;
    }
 
    /* Finalize and return: */
    LOGW("phornyac: insert_row(): INSERT succeeded, finalizing and returning");
    err = sqlite3_finalize(insertStmt);
    if (err != SQLITE_OK) {
        LOGW("phornyac: insert_row(): sqlite3_finalize() returned "
                "error: %s", sqlite3_errmsg(db));
        LOGW("phornyac: insert_row(): returning -1 due to errors");
        return -1;
    }
    return 0;
}

int add_policydb_entry(policy_entry *entry) {
    LOGW("phornyac: add_policydb_entry(): not implemented yet! "
            "...returning -1");
    return -1;
}

int remove_policydb_entries(policy_entry *entry) {
    LOGW("phornyac: remove_policydb_entries(): not implemented yet! "
            "...returning -1");
    return -1;
}

int query_policydb(policy_entry *entry) {
    int ret, retval;
    int taint;
    char *process_name;
    char *dest_name;
    char *hostname;
    int app_status;
    char *query_str;
    int query_len;
    sqlite3_stmt *query_stmt;
    bool match;
    int matches;

    //LOGW("phornyac: query_policydb: entered");
    retval = -1;
    if (!db_ptr) {
        LOGW("phornyac: query_policydb: db_ptr is NULL, returning -1");
        retval = -1;
        return retval;
    }

    taint = entry->taint_tag;
    process_name = entry->process_name;
    dest_name = entry->dest_name;
    hostname = entry->hostname;
    app_status = entry->app_status;  /* unused right now */

    /* TODO: right now, we run queries that get all of the rows that
     * match a particular source app/process name, then scan through
     * these to check for taint/destination matches. The reason for
     * this is so that we can run our own matching functions (that
     * account for wildcards, subnets, etc.) on the taint and
     * destination columns; can this be incorporated into the SELECT
     * statement somehow?? */
    query_str = construct_query_string(process_name);  /* free later! */
    if (query_str == NULL) {
        LOGW("phornyac: query_policydb: construct_query_string() returned "
                "NULL, so returning -1");
        retval = -1;
        return retval;
    }
    LOGW("phornyac: query_policydb: construct_query_string() returned "
            "string %s", query_str);
    query_len = strlen(query_str);

    /**
     * Prepare the SQLite statement:
     * http://sqlite.org/c3ref/prepare.html
     *   (see this page for why we use query_len + 1)
     */
    //LOGW("phornyac: query_policydb: calling sqlite3_prepare_v2()");
    ret = sqlite3_prepare_v2(db_ptr, query_str, query_len + 1,
            &query_stmt, NULL);
    free(query_str);
    if (ret != SQLITE_OK) {
        LOGW("phornyac: query_policydb: sqlite3_prepare_v2() returned "
                "error: %s", sqlite3_errmsg(db_ptr));
        LOGW("phornyac: query_policydb: returning -1 due to errors");
        retval = -1;
        return retval;
    }

    /**
     * Evaluate the SQL statement: call sqlite3_step() to get the next matching
     * record, then call check_row_for_match() to see if the record matches the
     * policy entry's destination server and taint tag. Repeat, counting the
     * number of matches, until the statement evaluation is complete and
     * sqlite3_step() returns SQLITE_DONE.
     * No policy "evaluation" or "action" is taken here; we just count the
     * matches, and it's up to the caller (policyd) what to do with that
     * information.
     * http://sqlite.org/c3ref/step.html
     */
    //LOGW("phornyac: query_policydb: evaluating the statement by calling "
    //        "sqlite3_step() repeatedly");
    matches = 0;
    ret = SQLITE_OK;
    while (ret != SQLITE_DONE) {
        //LOGW("phornyac: query_policydb: calling sqlite3_step()");
        ret = sqlite3_step(query_stmt);

        if (ret == SQLITE_ROW) {
            //print_row(query_stmt);
            if (USE_HOSTNAME)
                match = check_row_for_match(query_stmt,
                        (const char *)process_name, hostname, taint);
            else
                match = check_row_for_match(query_stmt,
                        (const char *)process_name, dest_name, taint);
            if (match) {
                matches++;
                LOGW("phornyac: query_policydb: found a match, incremented "
                        "matches to %d", matches);
           } 
        } else if (ret != SQLITE_DONE) {
            LOGW("phornyac: query_policydb: sqlite3_step() returned "
                    "error: %s", sqlite3_errmsg(db_ptr));
            LOGW("phornyac: query_policydb: returning -1 due to errors");
            retval = -1;
            goto finalize_and_out;
        }
    }

    retval = matches;
    //LOGW("phornyac: query_policydb: sqlite3_step() returned SQLITE_DONE, "
    //        "so loop completed, returning retval (matches)=%d", retval);
finalize_and_out:
    //LOGW("phornyac: query_policydb: finalizing query_stmt and returning");
    sqlite3_finalize(query_stmt);
    return retval;
}

void print_xml_node(xmlTextReaderPtr reader) {
    xmlChar *name = NULL;
    xmlChar *value = NULL;
    int depth, type, is_empty;

    name = xmlTextReaderName(reader);
    if (name == NULL)
        name = xmlStrdup(BAD_CAST "--");  //what does this mean???
    value = xmlTextReaderValue(reader);
    depth = xmlTextReaderDepth(reader);
    type = xmlTextReaderNodeType(reader);
    is_empty = xmlTextReaderIsEmptyElement(reader);

    LOGW("phornyac: print_xml_node: depth=%d, type=%d, name=%s, value=%s, "
            "is_empty=%d", depth, type, (name!=NULL) ? (char *)name : "NULL",
            (value!=NULL) ? (char *)value : "NULL", is_empty);
    if (name)
        xmlFree(name);
    if (value)
        xmlFree(value);
}

#define RULEDEPTH 1

/* Entirely process a depth-0 XML node, which should correspond to one
 * "rule" that we want to add to the database. The reader should point
 * at the "start element" depth-0 XML node to start, and will be advanced
 * just past the "end element" node for this depth-0 node before returning
 * successfully.
 *
 * IMPORTANT: for XML node types, see http://xmlsoft.org/xmlreader.html
 * 
 * Returns the value of xmlTextReaderRead() on success, or negative on error.
 */
int process_xmlnode_depth_zero(xmlTextReaderPtr reader) {
    LOGW("phornyac: process_xmlnode_depth_zero(): entered");
    xmlChar *name = NULL;
    xmlChar *value = NULL;
    int type;
    int cur_element = -1;
    int ret;
    /* The following items actually go in the db row: */
    xmlChar *source = NULL;  //type should be "typedef unsigned char xmlChar"
    xmlChar *dest = NULL;
    xmlChar *taint = NULL;

    /* Sample file:
     *   <?xml version="1.0"?>
     *   <rule prop1="test property 1" prop2="&amp; test prop 2">
     *     <source>com.android.browser</source>
     *     <dest>72.14.*</dest>
     *     <taint>255</taint>
     *   </rule>
     */
    
    LOGW("phornyac: process_xmlnode_depth_zero: printing start xml node");
    print_xml_node(reader);

    /* We expect the current node to have depth 0 and to be the start of
     * an element. For now, we only expect depth-0 nodes to have the
     * name "rule". */
    name = xmlTextReaderName(reader);
    if ((xmlTextReaderDepth(reader) != RULEDEPTH) ||
        (xmlTextReaderNodeType(reader) != 1) ||
        (strncmp((char *)name, root_name, strlen(root_name)) != 0)) {
        LOGW("phornyac: process_xmlnode_depth_zero: invalid node, "
                "advancing and returning");
        xmlFree(name);
        ret = xmlTextReaderRead(reader);
        return ret;
    }
    xmlFree(name);

    /* Loop until we reach another node of depth RULEDEPTH... */
    ret = xmlTextReaderRead(reader);
    while ((ret == 1) && (xmlTextReaderDepth(reader) > RULEDEPTH)) {
        LOGW("phornyac: process_xmlnode_depth_zero: start of while loop, "
                "printing xml node");
        print_xml_node(reader);

        type = xmlTextReaderNodeType(reader);
        switch(type) {
        case 1:
            /* Remember the type of element we're starting with cur_element: */
            name = xmlTextReaderName(reader);
            LOGW("phornyac: process_xmlnode_depth_zero: start element, name=%s", name);
            if (cur_element != -1) {
                //XXX: if this happens, means we have deeper nesting...
                //  which we don't handle yet.
                LOGW("phornyac: process_xmlnode_depth_zero: warning, "
                        "cur_element is %d, not -1 as expected!", cur_element);
            }
//            LOGW("phornyac: process_xmlnode_depth_zero: name=%s, "
//                    "db_col_names[SOURCE]=%s, strlen(db_col_names[SOURCE])=%d",
//                    (char *)name, db_col_names[SOURCE],
//                    strlen(db_col_names[SOURCE]));
//            LOGW("phornyac: process_xmlnode_depth_zero: name=%s, "
//                    "db_col_names[DEST]=%s, strlen(db_col_names[DEST])=%d",
//                    (char *)name, db_col_names[DEST],
//                    strlen(db_col_names[DEST]));
//            LOGW("phornyac: process_xmlnode_depth_zero: name=%s, "
//                    "db_col_names[TAINT]=%s, strlen(db_col_names[TAINT])=%d",
//                    (char *)name, db_col_names[TAINT],
//                    strlen(db_col_names[TAINT]));
            if (strncmp((char *)name, db_col_names[SOURCE],
                        strlen(db_col_names[SOURCE])) == 0) {
                LOGW("phornyac: process_xmlnode_depth_zero: setting "
                        "cur_element to SOURCE");
                cur_element = SOURCE;
            } else if (strncmp((char *)name, db_col_names[DEST],
                               strlen(db_col_names[DEST])) == 0) {
                LOGW("phornyac: process_xmlnode_depth_zero: setting "
                        "cur_element to DEST");
                cur_element = DEST;
            } else if (strncmp((char *)name, db_col_names[TAINT],
                               strlen(db_col_names[TAINT])) == 0) {
                LOGW("phornyac: process_xmlnode_depth_zero: setting "
                        "cur_element to TAINT");
                cur_element = TAINT;
            } else {
                LOGW("phornyac: process_xmlnode_depth_zero: unknown element "
                        "name, setting cur_element to -1");
                cur_element = -1;
            }
            xmlFree(name);
            break;
        case 3:
            /* Grab the value and store it in preparation for using it in
             * a database row: */
            value = xmlTextReaderValue(reader);
            LOGW("phornyac: process_xmlnode_depth_zero: text node, value=%s",
                    value);
            switch(cur_element) {
            case SOURCE:
                if (source) {
                    LOGW("phornyac: process_xmlnode_depth_zero: source is "
                            "not NULL; this is unexpected, freeing it "
                            "before overwriting");
                    xmlFree(source);
                }
                source = xmlStrdup(value);
                LOGW("phornyac: process_xmlnode_depth_zero: saved source=%s",
                        source);
                break;
            case DEST:
                if (dest) {
                    LOGW("phornyac: process_xmlnode_depth_zero: dest is "
                            "not NULL; this is unexpected, freeing it "
                            "before overwriting");
                    xmlFree(dest);
                }
                dest = xmlStrdup(value);
                LOGW("phornyac: process_xmlnode_depth_zero: saved dest=%s",
                        dest);
                break;
            case TAINT:
                if (taint) {
                    LOGW("phornyac: process_xmlnode_depth_zero: taint is "
                            "not NULL; this is unexpected, freeing it "
                            "before overwriting");
                    xmlFree(taint);
                }
                taint = xmlStrdup(value);
                LOGW("phornyac: process_xmlnode_depth_zero: saved taint=%s",
                        taint);
                break;
            default:
                LOGW("phornyac: process_xmlnode_depth_zero: unexpected value "
                        "for cur_element, doing nothing");
                break;
            }
            xmlFree(value);
            break;
        case 15:
            /* Reset the cur_element that we're keeping track of and insert
             * a new database row:*/
            name = xmlTextReaderName(reader);
            LOGW("phornyac: process_xmlnode_depth_zero: end element, name=%s",
                    (char *)name);
            xmlFree(name);
            if (cur_element == -1) {
                LOGW("phornyac: process_xmlnode_depth_zero: cur_element is -1, "
                        "so we lost the start element; doing nothing here");
                break;
            }
            cur_element = -1;
            break;
        default:
            LOGW("phornyac: process_xmlnode_depth_zero: ignoring node "
                    "with type=%d", type);
            break;
        }

        /* Advance to the next node: */
        ret = xmlTextReaderRead(reader);
    }

    /* We expect to break out of the loop when we've reached the "end element"
     * node of depth 0. */
    if (xmlTextReaderDepth(reader) != RULEDEPTH) {
        LOGW("phornyac: process_xmlnode_depth_zero: ended up in an "
                "unexpected place, ret=%d, depth=%d; returning -1",
                ret, xmlTextReaderDepth(reader));
        return -1;
    }
    if (xmlTextReaderNodeType(reader) != 15) {
        LOGW("phornyac: process_xmlnode_depth_zero: ended up in an "
                "unexpected place, ret=%d, type=%d; returning -1",
                ret, xmlTextReaderNodeType(reader));
        return -1;
    }

    /* If we've reached here, then we finally want to insert the values
     * we've saved as a new db row: */
    //TODO: if source or dest or taint wasn't specified, make it a
    //  wildcard?? Right now, insert_row() just returns an error.
    ret = insert_row(db_ptr, db_tablename,
            (char *)source, (char *)dest, (char *)taint);
    if (source)
        xmlFree(source);
    if (dest)
        xmlFree(dest);
    if (taint)
        xmlFree(taint);
    ///* I hope that xmlFree sets the pointers to NULL, but I'm not sure. */
    //if (source || dest || taint) {
    //    LOGW("phornyac: process_xmlnode_depth_zero: WARNING, "
    //            "xmlFree() does not reset pointers to NULL, "
    //            "need to go back and account for this!");
    //}
    if (ret) {
        LOGW("phornyac: process_xmlnode_depth_zero: insert_row() "
                "returned error=%d, so returning -1", ret);
        /* Everything should be cleaned up by now */
        return -1;
    }

    /* Finally, advance just past the "end element" node for the
     * depth-zero node we just processed, and return. */
    ret = xmlTextReaderRead(reader);
    if (ret < 0) {
        LOGW("phornyac: process_xmlnode_depth_zero: final "
                "xmlTextReaderRead() returned error=%d, returning -1",
                ret);
        return -1;
    }
    LOGW("phornyac: process_xmlnode_depth_zero: success, returning ret=%d "
            "from last xmlTextReaderRead()", ret);
    return ret;
}

/**
 * Creates a database table in the given database. Uses DROP TABLE
 * command to first clear out the existing database table.
 * I have no idea how to do this extensibly...
 * 
 * Returns: 0 on success, negative on error.
 */
int create_db_table(sqlite3 *db) {
    LOGW("phornyac: create_db_table(): entered");
    int ret;
    char *errmsg = NULL;

    if (db == NULL) {
        LOGW("phornyac: create_db_table(): error, db is NULL, "
                "returning -1");
        return -1;
    }
    //TODO: more precondition checking here??

    /**
     * Delete the table if it already exists. It's probably a better idea
     * to actually check if the table exists or not before attempting to
     * delete it (which will presumably cause an error if the table isn't
     * actually there), but oh well.
     * See: http://www.1keydata.com/sql/sqldrop.html
     */
    LOGW("phornyac: create_db_table(): calling sqlite3_exec to clear out "
            "table \"%s\"", db_tablename);
    ret = sqlite3_exec(db, db_dropstring, NULL, NULL, &errmsg);
    if (ret) {
        if (errmsg) {
            LOGW("phornyac: create_db_table(): sqlite3_exec(DROP TABLE) "
                    "returned error \"%s\", ignoring", errmsg);
            sqlite3_free(errmsg);
        } else {
            LOGW("phornyac: create_db_table(): sqlite3_exec(DROP TABLE) "
                    "returned error NULL, ignoring");
        }
    }

    /**
     * Create the table:
     * See http://sqlite.org/lang_createtable.html
     * See http://sqlite.org/c3ref/exec.html
     */
    LOGW("phornyac: create_db_table(): calling sqlite3_exec to create "
            "table \"%s\"", db_tablename);
    ret = sqlite3_exec(db, db_createstring, NULL, NULL, &errmsg);
    if (ret) {
        if (errmsg) {
            LOGW("phornyac: create_db_table(): sqlite3_exec(CREATE TABLE) "
                    "returned error \"%s\"", errmsg);
            sqlite3_free(errmsg);
        } else {
            LOGW("phornyac: create_db_table(): sqlite3_exec(CREATE TABLE) "
                    "returned error, errmsg=NULL");
        }
        LOGW("phornyac: create_db_table(): returning -1 due to errors");
        db_ptr = NULL;  /* Good idea? */
        return -1;
    }
    LOGW("phornyac: create_db_table(): successfully created table, returning");
    return 0;
}

int refresh_policydb() {
    int ret;
    xmlTextReaderPtr reader;
    LOGW("phornyac: refresh_policydb(): entered");

    if (!db_ptr) {
        LOGW("phornyac: refresh_policydb(): db_ptr is NULL, goto return_err");
        goto return_err;
    }

    LOGW("phornyac: refresh_policydb(): calling create_db_table() to "
            "clear out existing db and create new table");
    ret = create_db_table(db_ptr);
    if (ret < 0) {
        LOGW("phornyac: refresh_policydb(): create_db_table() returned "
                "error=%d, goto return_err", ret);
        goto return_err;
    }

    /* Parse the XML input file: */
    reader = xmlNewTextReaderFilename(policydb_xmlfile);
    if (reader == NULL) {
        LOGW("phornyac: refresh_policydb(): xmlNewTextReaderFilename(%s) "
                "failed, goto return_err", policydb_xmlfile);
        goto return_err;
    }
    ret = xmlTextReaderRead(reader);
    while (ret == 1) {
        LOGW("phornyac: refresh_policydb(): start of while loop, "
                "printing node");
        print_xml_node(reader);
        /* We process the XML file by calling a particular function to handle
         * each type of node at depth 0 of the XML tree. We expect that the
         * handling function will advance the reader just past the "end
         * element" node for the zero-depth node it just processed, which
         * will presumably leave the reader pointing at a "start element"
         * node for the next zero-depth node (or the end of the file), and
         * we'll never hit the else case here. */
        if (xmlTextReaderDepth(reader) == RULEDEPTH) {
            LOGW("phornyac: refresh_policydb(): depth is 1, processing node");
            ret = process_xmlnode_depth_zero(reader);
        } else {
            LOGW("phornyac: refresh_policydb(): xmlTextReaderDepth() "
                    "is not 1, ignoring this node");
            ret = xmlTextReaderRead(reader);  /* next node */
        }
    }
    /* Free reader resources; 0 return value means EOF, otherwise error */
    xmlFreeTextReader(reader);
    if (ret != 0) {
        LOGW("phornyac: refresh_policydb(): parse error, ret=%d; "
                "goto return_err", ret);
        goto return_err;
    }

    return 0;

return_err:
    LOGW("phornyac: refresh_policydb(): returning -1");
    return -1;
}

/**
 * Writes a default XML policy to the policydb XML file.
 * The default policy is empty for now.
 * Returns: 0 on success, negative on error.
 */
int create_default_policy_file() {
    int ret, fd, perms;
    LOGW("phornyac: create_default_policy_file: entered");

    /* Create the file: */
    perms = S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH;
    fd = creat(policydb_xmlfile, perms);
    if (fd < 0) {
        LOGW("phornyac: create_default_policy_file: open(%s) returned "
                "error=%d, returning -1", policydb_xmlfile,
                errno);
        return -1;
    }

    /* Write an "empty" policy to the file; can't just leave it blank,
     * or subsequent XML parsing will fail. */
    const char *empty_xml =
        "<?xml version=\"1.0\"?>\n<policy>\n</policy>";
    int size =
        strlen("<?xml version=\"1.0\"?>") + 1 +
        strlen("<policy>") + 1 +
        strlen("</policy>");
    LOGW("phornyac: create_default_policy_file: writing empty XML "
            "policy of size %d to fd=%d: \n%s", size, fd, empty_xml);
    ret = write(fd, empty_xml, size);
    if (ret < 0) {
        LOGW("phornyac: create_default_policy_file: write() returned "
                "error=%d, returning -1", errno);
        return -1;
    } else if (ret != size) {
        LOGW("phornyac: create_default_policy_file: write() wrote "
                "%d of %d bytes; not an error, but treating it like "
                "it is, returning -1", ret, size);
        return -1;
    }
    
    /* Ok, we're done: */
    ret = close(fd);
    if (ret < 0) {
        LOGW("phornyac: create_default_policy_file: close(%d) returned "
                "error=%d, returning -1", fd, errno);
        return -1;
    }
    LOGW("phornyac: create_default_policy_file: successfully created "
            "policy xml file %s", policydb_xmlfile);
    return 0;
}

int initialize_policydb() {
    LOGW("phornyac: initialize_policydb(): entered");
    int ret;
    struct stat st;

    if (db_ptr != NULL) {
        LOGW("phornyac: initialize_policydb(): error, db_ptr pointer is "
                "not NULL! Returning -1");
        return -1;
    }
    
    /**
     * Initialize the database connection if not already done:
     * http://sqlite.org/c3ref/open.html
     */
#ifdef TESTCODE
    LOGW("phornyac: initialize_policydb(): calling stat for db_file=%s",
            db_file);
    ret = stat(db_file, &st);
    if (ret) {
        if (errno == ENOENT) {
            LOGW("phornyac: initialize_policydb(): stat returned errno=ENOENT, "
                    "db file does not exist yet");
        } else {
            LOGW("phornyac: initialize_policydb(): stat returned other errno=%d",
                    errno);
        }
    } else {
            LOGW("phornyac: initialize_policydb(): stat succeeded, db file exists");
    }
#endif

    /**
     * The "standard" version of sqlite3_open() opens a database for reading
     * and writing, and creates it if it does not exist.
     * XXX: for some reason, sqlite3_open() gets an error when it tries to
     *   create the database file the very first time on boot. Why??
     *   "sqlite3_open() error message: unable to open database file"
     * http://sqlite.org/c3ref/open.html
     */
    LOGW("phornyac: initialize_policydb(): calling sqlite3_open(%s)",
            db_file);
    //ret = sqlite3_open(db_file, &db_ptr);
    ret = sqlite3_open_v2(db_file, &db_ptr,
            SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
    if ((ret != SQLITE_OK) || (db_ptr == NULL)) {
        if (db_ptr == NULL) {
            LOGW("phornyac: initialize_policydb(): sqlite3_open() returned "
                    "NULL db_ptr!");
        }
        LOGW("phornyac: initialize_policydb(): sqlite3_open() error message: "
                "%s", sqlite3_errmsg(db_ptr));
        db_ptr = NULL;  /* Good idea? */
        LOGW("phornyac: initialize_policydb(): returning -1 due to errors");
        return -1;
    }
    LOGW("phornyac: initialize_policydb(): sqlite3_open() succeeded, "
            "db_ptr=%p", db_ptr);

    /* Check for the existence of the policy XML file, and create a
     * blank file if it's not there: */
    ret = stat(policydb_xmlfile, &st);
    if (ret) {
        if (errno == ENOENT) {
            LOGW("phornyac: initialize_policydb(): stat returned errno=ENOENT, "
                    "xml file does not exist yet");
            ret = create_default_policy_file();
            if (ret < 0) {
                LOGW("phornyac: initialize_policydb(): "
                        "create_default_policy_file() returned "
                        "error=%d, goto close_err_exit", ret);
                goto close_err_exit;
            }
            LOGW("phornyac: initialize_policydb(): successfully created "
                    "policy xml file %s", policydb_xmlfile);
        } else {
            LOGW("phornyac: initialize_policydb(): stat returned other "
                    "errno=%d, goto close_err_exit", errno);
            goto close_err_exit;
        }
    } else {
        LOGW("phornyac: initialize_policydb(): stat succeeded, xml file "
                "already exists");
    }

    /* Fill in the database table from the policy XML file: */
    LOGW("phornyac: initialize_policydb(): calling refresh_policydb() "
            "to init table");
    ret = refresh_policydb();
    if (ret < 0) {
        LOGW("phornyac: initialize_policydb(): refresh_policydb() returned "
                "error %d, goto close_err_exit", ret);
        goto close_err_exit;
    }

    return 0;

close_err_exit:
    ret = sqlite3_close(db_ptr);
    if (ret != SQLITE_OK) {
        LOGW("phornyac: initialize_policydb(): sqlite3_close() returned "
                "error=%d, whatever", ret);
    }
    LOGW("phornyac: initialize_policydb(): returning -1");
    return -1;
}

