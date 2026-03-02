// Copyright (C) 2025 Christian Rößner
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

// Package privilege implements chroot and privilege-drop (setuid/setgid) for the Nauthilus server process.
package privilege

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

// essentialChrootFiles lists files that must exist inside the chroot for DNS resolution to work.
var essentialChrootFiles = []string{
	"/etc/resolv.conf",
	"/etc/nsswitch.conf",
	"/etc/hosts",
}

// idBitSize is the bit size used when parsing UID/GID strings.
const idBitSize = 32

// resolvedIdentity holds numeric UID/GID and supplementary groups resolved before chroot
// (when /etc/passwd and /etc/group are still available).
type resolvedIdentity struct {
	supplementaryGIDs []int
	uid               int
	gid               int
	hasUID            bool
	hasGID            bool
}

// parseInt parses a numeric ID string (UID or GID) and returns it as int.
func parseInt(s, label string) (int, error) {
	v, err := strconv.ParseInt(s, 10, idBitSize)
	if err != nil {
		return 0, fmt.Errorf("parse %s %q: %w", label, s, err)
	}

	return int(v), nil
}

// resolveIdentity looks up user and group names and returns their numeric IDs.
// This must be called before chroot, because /etc/passwd and /etc/group are unavailable afterwards.
func resolveIdentity(username, groupname string) (*resolvedIdentity, error) {
	id := &resolvedIdentity{}

	if username != "" {
		u, err := user.Lookup(username)
		if err != nil {
			return nil, fmt.Errorf("user lookup %q: %w", username, err)
		}

		uid, err := parseInt(u.Uid, "uid")
		if err != nil {
			return nil, err
		}

		gid, err := parseInt(u.Gid, "gid")
		if err != nil {
			return nil, err
		}

		id.uid = uid
		id.gid = gid
		id.hasUID = true
		id.hasGID = true

		supGIDs, err := resolveSupplementaryGroups(u)
		if err != nil {
			return nil, err
		}

		id.supplementaryGIDs = supGIDs
	}

	if groupname != "" {
		g, err := user.LookupGroup(groupname)
		if err != nil {
			return nil, fmt.Errorf("group lookup %q: %w", groupname, err)
		}

		gid, err := parseInt(g.Gid, "gid")
		if err != nil {
			return nil, err
		}

		id.gid = gid
		id.hasGID = true
	}

	return id, nil
}

// resolveSupplementaryGroups looks up all supplementary group IDs for the given user.
func resolveSupplementaryGroups(u *user.User) ([]int, error) {
	groupIDs, err := u.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("supplementary group lookup for %q: %w", u.Username, err)
	}

	gids := make([]int, 0, len(groupIDs))

	for _, gidStr := range groupIDs {
		gid, err := parseInt(gidStr, "supplementary gid")
		if err != nil {
			return nil, err
		}

		gids = append(gids, gid)
	}

	return gids, nil
}

// validateChrootFiles checks that essential DNS-related files exist inside the chroot directory.
func validateChrootFiles(chrootPath string) error {
	for _, f := range essentialChrootFiles {
		target := chrootPath + f

		if _, err := os.Stat(target); os.IsNotExist(err) {
			return fmt.Errorf("essential file missing in chroot: %s", target)
		}
	}

	return nil
}

// applyChrootAndDrop performs the actual chroot and setgid/setuid syscalls.
func applyChrootAndDrop(chrootPath string, id *resolvedIdentity) error {
	if chrootPath != "" {
		if err := syscall.Chroot(chrootPath); err != nil {
			return fmt.Errorf("chroot to %q: %w", chrootPath, err)
		}

		if err := os.Chdir("/"); err != nil {
			return fmt.Errorf("chdir after chroot: %w", err)
		}
	}

	// Set supplementary groups before primary group and user.
	if len(id.supplementaryGIDs) > 0 {
		if err := syscall.Setgroups(id.supplementaryGIDs); err != nil {
			return fmt.Errorf("setgroups: %w", err)
		}
	}

	// Set group before user, because setuid drops root privileges.
	if id.hasGID {
		if err := syscall.Setgid(id.gid); err != nil {
			return fmt.Errorf("setgid %d: %w", id.gid, err)
		}
	}

	if id.hasUID {
		if err := syscall.Setuid(id.uid); err != nil {
			return fmt.Errorf("setuid %d: %w", id.uid, err)
		}
	}

	return nil
}

// DropPrivileges performs user/group lookup, chroot, and privilege drop in the correct order.
//
// The sequence is:
//  1. Resolve user/group to numeric UID/GID (before chroot, needs /etc/passwd).
//  2. Validate essential DNS files inside the chroot directory.
//  3. chroot() into the target directory.
//  4. setgroups() — sets supplementary groups while still root.
//  5. setgid() — must happen before setuid() to retain root for the call.
//  6. setuid() — last step, drops all remaining privileges.
//
// All parameters are optional. If all are empty, DropPrivileges is a no-op.
func DropPrivileges(username, groupname, chrootPath string) error {
	if username == "" && groupname == "" && chrootPath == "" {
		return nil
	}

	id, err := resolveIdentity(username, groupname)
	if err != nil {
		return err
	}

	if chrootPath != "" {
		if err := validateChrootFiles(chrootPath); err != nil {
			return err
		}
	}

	return applyChrootAndDrop(chrootPath, id)
}
