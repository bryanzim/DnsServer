/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using TechnitiumLibrary.IO;

namespace DnsServerCore.Auth
{
    enum PermissionSection : byte
    {
        Unknown = 0,
        Dashboard = 1,
        Zones = 2,
        Cache = 3,
        Allowed = 4,
        Blocked = 5,
        Apps = 6,
        DnsClient = 7,
        Settings = 8,
        DhcpServer = 9,
        Administration = 10,
        Logs = 11
    }

    [Flags]
    enum PermissionFlag : byte
    {
        None = 0,
        View = 1,
        Modify = 2,
        Delete = 4,
        ViewModify = 3,
        ViewModifyDelete = 7
    }

    class Permission : IComparable<Permission>
    {
        #region variables

        readonly PermissionSection _section;
        readonly string _subItemName;

        readonly ConcurrentDictionary<User, PermissionFlag> _userPermissions;
        readonly ConcurrentDictionary<Group, PermissionFlag> _groupPermissions;

        readonly ConcurrentDictionary<string, Permission> _subItemPermissions;

        #endregion

        #region constructor

        public Permission(PermissionSection section, string subItemName = null)
        {
            _section = section;
            _subItemName = subItemName;

            _userPermissions = new ConcurrentDictionary<User, PermissionFlag>(1, 1);
            _groupPermissions = new ConcurrentDictionary<Group, PermissionFlag>(1, 1);

            _subItemPermissions = new ConcurrentDictionary<string, Permission>(1, 1);
        }

        public Permission(BinaryReader bR, IReadOnlyDictionary<string, User> users, IReadOnlyDictionary<string, Group> groups)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                    _section = (PermissionSection)bR.ReadByte();

                    {
                        int count = bR.ReadByte();
                        _userPermissions = new ConcurrentDictionary<User, PermissionFlag>(1, count);

                        for (int i = 0; i < count; i++)
                        {
                            string username = bR.BaseStream.ReadShortString().ToLowerInvariant();
                            PermissionFlag flag = (PermissionFlag)bR.ReadByte();

                            if (users.TryGetValue(username, out User user))
                                _userPermissions.TryAdd(user, flag);
                        }
                    }

                    {
                        int count = bR.ReadByte();
                        _groupPermissions = new ConcurrentDictionary<Group, PermissionFlag>(1, count);

                        for (int i = 0; i < count; i++)
                        {
                            string groupName = bR.BaseStream.ReadShortString().ToLowerInvariant();
                            PermissionFlag flag = (PermissionFlag)bR.ReadByte();

                            if (groups.TryGetValue(groupName, out Group group))
                                _groupPermissions.TryAdd(group, flag);
                        }
                    }

                    {
                        int count;

                        if (version >= 2)
                            count = bR.ReadInt32();
                        else
                            count = bR.ReadByte();

                        _subItemPermissions = new ConcurrentDictionary<string, Permission>(1, count);

                        for (int i = 0; i < count; i++)
                        {
                            string subItemName = bR.BaseStream.ReadShortString();
                            Permission subItemPermission = new Permission(bR, users, groups);

                            _subItemPermissions.TryAdd(subItemName.ToLowerInvariant(), subItemPermission);
                        }
                    }

                    break;

                default:
                    throw new InvalidDataException("Invalid data or version not supported.");
            }
        }

        #endregion

        #region public

        public void SetPermission(User user, PermissionFlag flags)
        {
            _userPermissions[user] = flags;
        }

        public void SyncPermissions(IReadOnlyDictionary<User, PermissionFlag> userPermissions)
        {
            //remove non-existent permissions
            foreach (KeyValuePair<User, PermissionFlag> userPermission in _userPermissions)
            {
                if (!userPermissions.ContainsKey(userPermission.Key))
                    _userPermissions.TryRemove(userPermission.Key, out _);
            }

            //set new permissions
            foreach (KeyValuePair<User, PermissionFlag> userPermission in userPermissions)
                _userPermissions[userPermission.Key] = userPermission.Value;
        }

        public void SyncSubItemPermissions(IReadOnlyDictionary<string, Permission> subItemPermissions)
        {
            List<string> removedSubItems = new List<string>();

            foreach (KeyValuePair<string, Permission> existingSubItem in _subItemPermissions)
            {
                if (!subItemPermissions.ContainsKey(existingSubItem.Key))
                    removedSubItems.Add(existingSubItem.Key);
            }

            foreach (string removedSubItem in removedSubItems)
                _subItemPermissions.TryRemove(removedSubItem, out _);

            foreach (KeyValuePair<string, Permission> subItemPermission in subItemPermissions)
            {
                Permission localSubItem = _subItemPermissions.GetOrAdd(subItemPermission.Key, delegate (string key)
                {
                    return new Permission(_section, key);
                });

                localSubItem.SyncPermissions(subItemPermission.Value.UserPermissions);
                localSubItem.SyncPermissions(subItemPermission.Value.GroupPermissions);
            }
        }

        public void SetSubItemPermission(string subItemName, User user, PermissionFlag flags)
        {
            Permission subItemPermission = _subItemPermissions.GetOrAdd(subItemName.ToLowerInvariant(), delegate (string key)
            {
                return new Permission(_section, key);
            });

            subItemPermission.SetPermission(user, flags);
        }

        public void SetPermission(Group group, PermissionFlag flags)
        {
            _groupPermissions[group] = flags;
        }

        public void SyncPermissions(IReadOnlyDictionary<Group, PermissionFlag> groupPermissions)
        {
            //remove non-existent permissions
            foreach (KeyValuePair<Group, PermissionFlag> groupPermission in _groupPermissions)
            {
                if (!groupPermissions.ContainsKey(groupPermission.Key))
                    _groupPermissions.TryRemove(groupPermission.Key, out _);
            }

            //set new permissions
            foreach (KeyValuePair<Group, PermissionFlag> groupPermission in groupPermissions)
                _groupPermissions[groupPermission.Key] = groupPermission.Value;
        }

        public void SetSubItemPermission(string subItemName, Group group, PermissionFlag flags)
        {
            Permission subItemPermission = _subItemPermissions.GetOrAdd(subItemName.ToLowerInvariant(), delegate (string key)
            {
                return new Permission(_section, key);
            });

            subItemPermission.SetPermission(group, flags);
        }

        public bool RemovePermission(User user)
        {
            return _userPermissions.TryRemove(user, out _);
        }

        public bool RemoveSubItemPermission(string subItemName, User user)
        {
            return _subItemPermissions.TryGetValue(subItemName.ToLowerInvariant(), out Permission subItemPermission) && subItemPermission.RemovePermission(user);
        }

        public bool RemovePermission(Group group)
        {
            return _groupPermissions.TryRemove(group, out _);
        }

        public bool RemoveSubItemPermission(string subItemName, Group group)
        {
            return _subItemPermissions.TryGetValue(subItemName.ToLowerInvariant(), out Permission subItemPermission) && subItemPermission.RemovePermission(group);
        }

        public bool RemoveAllSubItemPermissions(User user)
        {
            bool removed = false;

            foreach (KeyValuePair<string, Permission> subItemPermission in _subItemPermissions)
            {
                if (subItemPermission.Value.RemovePermission(user))
                    removed = true;
            }

            return removed;
        }

        public bool RemoveAllSubItemPermissions(Group group)
        {
            bool removed = false;

            foreach (KeyValuePair<string, Permission> subItemPermission in _subItemPermissions)
            {
                if (subItemPermission.Value.RemovePermission(group))
                    removed = true;
            }

            return removed;
        }

        public bool RemoveAllSubItemPermissions(string subItemName)
        {
            return _subItemPermissions.TryRemove(subItemName, out _);
        }

        /// <summary>
        /// Removes the user's entries from this permission and all sub item permissions and returns them.
        /// User/Group hash by name, so entries must be detached before a rename and re-added via <see cref="ReattachPermissions(User, IReadOnlyList{KeyValuePair{Permission, PermissionFlag}})"/> after.
        /// </summary>
        public List<KeyValuePair<Permission, PermissionFlag>> DetachPermissions(User user)
        {
            List<KeyValuePair<Permission, PermissionFlag>> detached = new List<KeyValuePair<Permission, PermissionFlag>>();
            DetachPermissions(user, detached);
            return detached;
        }

        private void DetachPermissions(User user, List<KeyValuePair<Permission, PermissionFlag>> detached)
        {
            if (_userPermissions.TryRemove(user, out PermissionFlag flags))
                detached.Add(new KeyValuePair<Permission, PermissionFlag>(this, flags));

            foreach (KeyValuePair<string, Permission> subItemPermission in _subItemPermissions)
                subItemPermission.Value.DetachPermissions(user, detached);
        }

        public static void ReattachPermissions(User user, IReadOnlyList<KeyValuePair<Permission, PermissionFlag>> detached)
        {
            foreach (KeyValuePair<Permission, PermissionFlag> entry in detached)
                entry.Key.SetPermission(user, entry.Value);
        }

        /// <summary>
        /// Removes the group's entries from this permission and all sub item permissions and returns them.
        /// User/Group hash by name, so entries must be detached before a rename and re-added via <see cref="ReattachPermissions(Group, IReadOnlyList{KeyValuePair{Permission, PermissionFlag}})"/> after.
        /// </summary>
        public List<KeyValuePair<Permission, PermissionFlag>> DetachPermissions(Group group)
        {
            List<KeyValuePair<Permission, PermissionFlag>> detached = new List<KeyValuePair<Permission, PermissionFlag>>();
            DetachPermissions(group, detached);
            return detached;
        }

        private void DetachPermissions(Group group, List<KeyValuePair<Permission, PermissionFlag>> detached)
        {
            if (_groupPermissions.TryRemove(group, out PermissionFlag flags))
                detached.Add(new KeyValuePair<Permission, PermissionFlag>(this, flags));

            foreach (KeyValuePair<string, Permission> subItemPermission in _subItemPermissions)
                subItemPermission.Value.DetachPermissions(group, detached);
        }

        public static void ReattachPermissions(Group group, IReadOnlyList<KeyValuePair<Permission, PermissionFlag>> detached)
        {
            foreach (KeyValuePair<Permission, PermissionFlag> entry in detached)
                entry.Key.SetPermission(group, entry.Value);
        }

        public Permission GetSubItemPermission(string subItemName)
        {
            if (_subItemPermissions.TryGetValue(subItemName.ToLowerInvariant(), out Permission subItemPermission))
                return subItemPermission;

            return null;
        }

        public bool IsPermitted(User user, PermissionFlag flag)
        {
            if (_userPermissions.TryGetValue(user, out PermissionFlag userPermissions) && userPermissions.HasFlag(flag))
                return true;

            foreach (Group group in user.MemberOfGroups)
            {
                if (_groupPermissions.TryGetValue(group, out PermissionFlag groupPermissions) && groupPermissions.HasFlag(flag))
                    return true;
            }

            return false;
        }

        public bool IsSubItemPermitted(string subItemName, User user, PermissionFlag flag)
        {
            return _subItemPermissions.TryGetValue(subItemName.ToLowerInvariant(), out Permission subItemPermission) && subItemPermission.IsPermitted(user, flag);
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)2);
            bW.Write((byte)_section);

            {
                bW.Write(Convert.ToByte(_userPermissions.Count));

                foreach (KeyValuePair<User, PermissionFlag> userPermission in _userPermissions)
                {
                    bW.BaseStream.WriteShortString(userPermission.Key.Username);
                    bW.Write((byte)userPermission.Value);
                }
            }

            {
                bW.Write(Convert.ToByte(_groupPermissions.Count));

                foreach (KeyValuePair<Group, PermissionFlag> groupPermission in _groupPermissions)
                {
                    bW.BaseStream.WriteShortString(groupPermission.Key.Name);
                    bW.Write((byte)groupPermission.Value);
                }
            }

            {
                bW.Write(_subItemPermissions.Count);

                foreach (KeyValuePair<string, Permission> subItemPermission in _subItemPermissions)
                {
                    bW.BaseStream.WriteShortString(subItemPermission.Key);
                    subItemPermission.Value.WriteTo(bW);
                }
            }
        }

        public int CompareTo(Permission other)
        {
            return _section.CompareTo(other._section);
        }

        #endregion

        #region properties

        public PermissionSection Section
        { get { return _section; } }

        public string SubItemName
        { get { return _subItemName; } }

        public IReadOnlyDictionary<User, PermissionFlag> UserPermissions
        { get { return _userPermissions; } }

        public IReadOnlyDictionary<Group, PermissionFlag> GroupPermissions
        { get { return _groupPermissions; } }

        public IReadOnlyDictionary<string, Permission> SubItemPermissions
        { get { return _subItemPermissions; } }

        #endregion
    }
}
