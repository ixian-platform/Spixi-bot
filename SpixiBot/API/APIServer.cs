using IXICore;
using IXICore.Activity;
using IXICore.SpixiBot;
using Org.BouncyCastle.Utilities.Encoders;
using SpixiBot.Meta;
using SpixiBot.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;

namespace SpixiBot
{
    class APIServer : GenericAPIServer
    {
        public APIServer(List<string> listen_URLs, Dictionary<string, string> authorized_users = null, List<string> allowed_IPs = null, IActivityStorage activityStorage = null)
        {
            // Start the API server
            start(listen_URLs, authorized_users, allowed_IPs, activityStorage);
        }

        protected override bool processRequest(HttpListenerContext context, string methodName, Dictionary<string, object> parameters)
        {
            JsonResponse response = null;

            if (methodName.Equals("sb_settings", StringComparison.OrdinalIgnoreCase))
            {
                response = onSettings(parameters);
            }
            
            if (methodName.Equals("sb_setOption", StringComparison.OrdinalIgnoreCase))
            {
                response = onSetOption(parameters);
            }

            if (methodName.Equals("sb_getGroups", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetGroups(parameters);
            }

            if (methodName.Equals("sb_newGroup", StringComparison.OrdinalIgnoreCase))
            {
                response = onNewGroup(parameters);
            }

            if (methodName.Equals("sb_delGroup", StringComparison.OrdinalIgnoreCase))
            {
                response = onDelGroup(parameters);
            }

            if (methodName.Equals("sb_updateGroup", StringComparison.OrdinalIgnoreCase))
            {
                response = onUpdateGroup(parameters);
            }

            if (methodName.Equals("sb_getUsers", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetUsers(parameters);
            }

            if (methodName.Equals("sb_delUser", StringComparison.OrdinalIgnoreCase))
            {
                response = onDelUser(parameters);
            }

            if (methodName.Equals("sb_banUser", StringComparison.OrdinalIgnoreCase))
            {
                response = onBanUser(parameters);
            }

            if (methodName.Equals("sb_kickUser", StringComparison.OrdinalIgnoreCase))
            {
                response = onKickUser(parameters);
            }

            if (methodName.Equals("sb_setUserGroup", StringComparison.OrdinalIgnoreCase))
            {
                response = onSetUserGroup(parameters);
            }

            if (methodName.Equals("sb_getChannels", StringComparison.OrdinalIgnoreCase))
            {
                response = onGetChannels(parameters);
            }

            if (methodName.Equals("sb_newChannel", StringComparison.OrdinalIgnoreCase))
            {
                response = onNewChannel(parameters);
            }

            if (methodName.Equals("sb_delChannel", StringComparison.OrdinalIgnoreCase))
            {
                response = onDelChannel(parameters);
            }

            if (methodName.Equals("sb_updateChannel", StringComparison.OrdinalIgnoreCase))
            {
                response = onUpdateChannel(parameters);
            }

            if (methodName.Equals("sb_saveAvatar", StringComparison.OrdinalIgnoreCase))
            {
                string b64_data = (string)parameters["data"];
                b64_data = b64_data.Substring(b64_data.IndexOf("base64,") + 7);
                File.WriteAllBytes("avatar.jpg", Base64.Decode(b64_data));
                if(File.Exists("html/avatar.jpg"))
                {
                    File.Delete("html/avatar.jpg");
                }
                File.Copy("avatar.jpg", "html/avatar.jpg");
            }


            if (response == null)
            {
                return false;
            }

            // Set the content type to plain to prevent xml parsing errors in various browsers
            context.Response.ContentType = "application/json";

            sendResponse(context.Response, response);

            context.Response.Close();

            return true;
        }

        public JsonResponse onSettings(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Dictionary<string, object> status_array = new Dictionary<string, object>();

            status_array.Add("serverName", Node.settings.getOption("serverName", Config.botName));
            status_array.Add("serverDescription", Node.settings.getOption("serverDescription", ""));
            status_array.Add("serverPassword", Node.settings.getOption("serverPassword", ""));
            status_array.Add("allowFileTransfer", Node.settings.getOption("allowFileTransfer", "0"));
            status_array.Add("fileTransferLimitMB", Node.settings.getOption("fileTransferLimitMB", "10"));
            status_array.Add("defaultGroup", Node.groups.groupIndexToName(Int32.Parse(Node.settings.getOption("defaultGroup", "0"))));
            status_array.Add("defaultChannel", Node.channels.channelIndexToName(Int32.Parse(Node.settings.getOption("defaultChannel", "0"))));
            int intro = 0;
            if(Node.settings.getOption("serverName", "") == "")
            {
                intro = 1;
            }else if(Node.channels.channels.Count == 0)
            {
                intro = 2;
            }else if(Node.groups.groups.Count == 0)
            {
                intro = 3;
            }
            status_array.Add("intro", intro.ToString());

            return new JsonResponse { result = status_array, error = error };
        }

        public JsonResponse onSetOption(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            if (parameters.ContainsKey("serverName"))
            {
                Config.botName = (string)parameters["serverName"];
                Node.settings.setOption("serverName", (string)parameters["serverName"]);
            }

            if (parameters.ContainsKey("serverDescription"))
            {
                Node.settings.setOption("serverDescription", (string)parameters["serverDescription"]);
            }

            if (parameters.ContainsKey("serverPassword"))
            {
                Node.settings.setOption("serverPassword", (string)parameters["serverPassword"]);
            }

            if (parameters.ContainsKey("allowFileTransfer"))
            {
                Node.settings.setOption("allowFileTransfer", (string)parameters["allowFileTransfer"]);
            }

            if (parameters.ContainsKey("fileTransferLimitMB"))
            {
                Node.settings.setOption("fileTransferLimitMB", (string)parameters["fileTransferLimitMB"]);
            }

            if (parameters.ContainsKey("defaultGroup"))
            {
                Node.settings.setOption("defaultGroup", Node.groups.getGroup((string)parameters["defaultGroup"]).index.ToString());
            }

            if (parameters.ContainsKey("defaultChannel"))
            {
                Node.settings.setOption("defaultChannel", Node.channels.getChannel((string)parameters["defaultChannel"]).index.ToString());
            }

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onGetUsers(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Dictionary<string, object> contacts_array = new Dictionary<string, object>();

            lock (Node.users.contacts)
            {
                foreach (var contact in Node.users.contacts)
                {
                    Dictionary<string, object> contact_array = new Dictionary<string, object>();
                    contact_array.Add("nick", contact.Value.getNick());
                    int role = contact.Value.getPrimaryRole();
                    contact_array.Add("role", Node.groups.groupIndexToName(role));
                    contacts_array.Add(contact.Key.ToString(), contact_array);
                }
            }

            return new JsonResponse { result = contacts_array, error = error };
        }

        public JsonResponse onDelUser(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Node.users.delUser(new Address((string)parameters["address"]));

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onBanUser(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Node.users.getUser(new Address((string)parameters["address"])).status = BotContactStatus.banned;
            Node.users.writeContactsToFile();

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onKickUser(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Node.users.getUser(new Address((string)parameters["address"])).status = BotContactStatus.kicked;
            Node.users.writeContactsToFile();

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onSetUserGroup(Dictionary<string, object> parameters)
        {
            JsonError error = null;
            string role = (string)parameters["role"];
            var group = Node.groups.getGroup(role);
            int role_id = 0;
            if(group != null)
            {
                role_id = group.index;
            }
            Address address = new Address((string)parameters["address"]);
            Node.users.setRole(address, role_id);
            StreamProcessor.sendInfo(address);

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onGetChannels(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Dictionary<string, object> channels_array = new Dictionary<string, object>();

            lock (Node.channels.channels)
            {
                foreach (var channel in Node.channels.channels)
                {
                    channels_array.Add(channel.Key, channel.Value.channelName);
                }
            }

            return new JsonResponse { result = channels_array, error = error };
        }

        public JsonResponse onNewChannel(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            if (Node.channels.hasChannel((string)parameters["channel"]))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "Channel already exists." } };
            }

            BotChannel channel = new BotChannel(Node.channels.getNextIndex(), (string)parameters["channel"]);
            Node.channels.setChannel((string)parameters["channel"], channel);
            if ((string)parameters["default"] == "1")
            {
                Node.settings.setOption("defaultChannel", channel.index.ToString());
            }
            Node.settings.saveSettings();

            Messages.addChannel(channel);

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onUpdateChannel(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            if (!Node.channels.hasChannel((string)parameters["origChannel"]))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "Unknown channel." } };
            }

            var orig_channel = Node.channels.getChannel((string)parameters["origChannel"]);

            Node.channels.setChannel(orig_channel.channelName, new BotChannel(orig_channel.index, (string)parameters["channel"]));
            if ((string)parameters["default"] == "1")
            {
                Node.settings.setOption("defaultChannel", orig_channel.index.ToString());
            }
            Node.settings.saveSettings();

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onDelChannel(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Node.channels.setChannel((string)parameters["channel"], null);
            Node.settings.saveSettings();

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onGetGroups(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Dictionary<string, object> groups_array = new Dictionary<string, object>();

            lock (Node.groups.groups)
            {
                foreach (var group in Node.groups.groups)
                {
                    Dictionary<string, object> group_array = new Dictionary<string, object>();
                    group_array.Add("cost", group.Value.messageCost.ToString());
                    group_array.Add("admin", group.Value.admin.ToString());

                    groups_array.Add(group.Value.groupName, group_array);
                }
            }

            return new JsonResponse { result = groups_array, error = error };
        }

        public JsonResponse onDelGroup(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            Node.groups.setGroup((string)parameters["group"], null);
            Node.settings.saveSettings();

            return new JsonResponse { result = null, error = error };
        }

        public JsonResponse onNewGroup(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            string group = (string)parameters["group"];
            IxiNumber cost = new IxiNumber((string)parameters["cost"]);
            bool admin = false;
            if((string)parameters["admin"] == "1")
            {
                admin = true;
            }

            if (Node.groups.hasGroup(group))
            {
                return new JsonResponse { result = "", error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "Group already exists." } };
            }

            BotGroup new_group = new BotGroup(Node.groups.getNextIndex(), group, cost, admin);

            Node.groups.setGroup(group, new_group);
            if ((string)parameters["default"] == "1")
            {
                Node.settings.setOption("defaultGroup", new_group.index.ToString());
            }
            Node.settings.saveSettings();

            return new JsonResponse { result = "", error = error };
        }

        public JsonResponse onUpdateGroup(Dictionary<string, object> parameters)
        {
            JsonError error = null;

            string group = (string)parameters["group"];
            IxiNumber cost = new IxiNumber((string)parameters["cost"]);
            bool admin = false;
            if ((string)parameters["admin"] == "1")
            {
                admin = true;
            }

            if (!Node.groups.hasGroup((string)parameters["origGroup"]))
            {
                return new JsonResponse { result = null, error = new JsonError() { code = (int)RPCErrorCode.RPC_INVALID_PARAMETER, message = "Unknown group." } };
            }

            var orig_group = Node.groups.getGroup((string)parameters["origGroup"]);

            Node.groups.setGroup(orig_group.groupName, new BotGroup(orig_group.index, group, cost, admin));
            if ((string)parameters["default"] == "1")
            {
                Node.settings.setOption("defaultGroup", orig_group.index.ToString());
            }
            Node.settings.saveSettings();

            return new JsonResponse { result = "", error = error };
        }
    }
}
