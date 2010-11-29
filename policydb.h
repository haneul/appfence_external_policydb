/**
 * Peter Hornyack
 */

/**
 * Contains the policy database interface used only by the
 * policyd server; all of this should be invisible to the "client"
 * apps.
 */

#ifndef POLICYDB_H
#define POLICYDB_H

#include <policy_global.h>

/* File containing user-specified policy in XML format: */
const char *policydb_xmlfile = "/data/data/com.android.settings/policydb.xml";

/**
 * Add an entry to the policy db.
 * Returns: the number of added entries (should be 1) on success,
 *   -1 on error.
 */
int add_policydb_entry(policy_entry *entry);

/**
 * Remove entries from the policy db. If the supplied entry contains
 * wildcards, all matching entries will be removed from the db.
 * Returns: the number of entries removed on success (0 is valid),
 *   or -1 on error.
 */
int remove_policydb_entries(policy_entry *entry);

/**
 * Queries the policy db and returns the number of matching entries;
 * it's the caller's choice what to do with this information. The
 * supplied entry can contain wildcards.
 * Returns: the number of matching entries on success (0 is valid),
 *   or -1 on error.
 */
int query_policydb(policy_entry *entry);

/**
 * Tells the policy db to re-read its policy file that is stored on
 * persistent storage (policydb_xmlfile). This function will create
 * the table in the database if it does not already exist.
 * Returns: 0 on success, -1 on error.
 */
int refresh_policydb();

/**
 * Initialize the policy db for the first time. This function must
 * be called exactly once, before any of the other functions in this
 * interface are called.
 * Returns: 0 on success, negative on error.
 */
int initialize_policydb();

#endif
