using IXICore;
using IXICore.Meta;
using IXICore.Network;
using IXICore.SpixiBot;
using IXICore.Utils;
using SpixiBot.Meta;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SpixiBot.Network
{
    class StreamProcessor
    {
        static List<StreamMessage> pendingMessages = new List<StreamMessage>(); // List that stores pending/unpaid stream messages

        public static void init(string base_path = "")
        {
            Messages.init(base_path);
        }

        // Called when receiving S2 data from clients
        public static void receiveData(byte[] bytes, RemoteEndpoint endpoint)
        {
            // TODO Verify signature for all relevant messages

            string endpoint_wallet_string = endpoint.presence.wallet.ToString();
            Logging.info(string.Format("Receiving S2 data from {0}", endpoint_wallet_string));

            StreamMessage message = new StreamMessage(bytes);

            // Don't allow clients to send error stream messages, as it's reserved for S2 nodes only
            if(message.type == StreamMessageCode.error)
            {
                Logging.warn(string.Format("Discarding error message type from {0}", endpoint_wallet_string));
                return;
            }

            // Discard messages not sent to this node
            if(!IxianHandler.getWalletStorage().isMyAddress(message.recipient))
            {
                Logging.warn(string.Format("Discarding message that wasn't sent to this node from {0}", endpoint_wallet_string));
                return;
            }

            if (message.encryptionType != StreamMessageEncryptionCode.none && !message.decrypt(IxianHandler.getWalletStorage().getPrimaryPrivateKey(), null, null))
            {
                Logging.error("Could not decrypt message from {0}", message.sender.ToString());
                return;
            }

            SpixiMessage spixi_msg = new SpixiMessage(message.data);

            int channel = 0;
            if (spixi_msg != null)
            {
                channel = spixi_msg.channel;
            }

            if (message.requireRcvConfirmation)
            {
                switch (spixi_msg.type)
                {
                    case SpixiMessageCode.msgReceived:
                    case SpixiMessageCode.msgRead:
                    case SpixiMessageCode.requestFileData:
                    case SpixiMessageCode.fileData:
                    case SpixiMessageCode.appData:
                    case SpixiMessageCode.msgTyping:
                        // do not send received confirmation
                        break;

                    case SpixiMessageCode.chat:
                        sendReceivedConfirmation(message.sender, message.id, channel, endpoint);
                        break;

                    default:
                        sendReceivedConfirmation(message.sender, message.id, -1, endpoint);
                        break;
                }
            }

            switch (spixi_msg.type)
            {
                case SpixiMessageCode.requestAdd:
                    // Friend request
                    if (!new Address(spixi_msg.data).SequenceEqual(message.sender) || !message.verifySignature(spixi_msg.data))
                    {
                        Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", message.type, Crypto.hashToString(message.id), message.sender.ToString());
                    }
                    else
                    {
                        sendAcceptAdd(endpoint.presence.wallet, endpoint.presence.pubkey);
                        sendAvatar(endpoint.presence.wallet, null);
                    }
                    break;

                case SpixiMessageCode.requestAdd2:
                    // Friend request
                    var version_with_offset = spixi_msg.data.GetIxiVarUInt(0);
                    var pub_key_with_offset = spixi_msg.data.ReadIxiBytes(version_with_offset.bytesRead);
                    var pub_key = pub_key_with_offset.bytes;
                    if (!new Address(pub_key).SequenceEqual(message.sender) || !message.verifySignature(pub_key))
                    {
                        Logging.error("Unable to verify signature for message type: {0}, id: {1}, from: {2}.", message.type, Crypto.hashToString(message.id), message.sender.ToString());
                    }
                    else
                    {
                        sendAcceptAdd(endpoint.presence.wallet, endpoint.presence.pubkey);
                        sendAvatar(endpoint.presence.wallet, null);
                    }
                    break;
                    
                case SpixiMessageCode.getPubKey:
                    if (Node.users.hasUser(new Address(spixi_msg.data)))
                    {
                        StreamMessage sm = new StreamMessage();
                        sm.type = StreamMessageCode.info;
                        sm.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
                        sm.recipient = message.sender;
                        sm.data = new SpixiMessage(SpixiMessageCode.pubKey, Node.users.getUser(new Address(spixi_msg.data)).publicKey).getBytes();
                        sm.encryptionType = StreamMessageEncryptionCode.none;

                        sendMessage(endpoint.presence.wallet, sm);
                    }
                    break;

                case SpixiMessageCode.getNick:
                    sendNickname(endpoint.presence.wallet, spixi_msg.data);
                    break;

                case SpixiMessageCode.getAvatar:
                    sendAvatar(endpoint.presence.wallet, spixi_msg.data);
                    break;

                case SpixiMessageCode.nick:
                    Node.users.setPubKey(endpoint.presence.wallet, endpoint.serverPubKey, false);
                    Node.users.setNick(endpoint.presence.wallet, message.getBytes());
                    break;

                case SpixiMessageCode.avatar:
                    Node.users.setPubKey(endpoint.presence.wallet, endpoint.serverPubKey, false);
                    if (message.data.Length < 500000)
                    {
                        if (message.data == null)
                        {
                            Node.users.setAvatar(endpoint.presence.wallet, null);
                        }
                        else
                        {
                            Node.users.setAvatar(endpoint.presence.wallet, message.getBytes());
                        }
                    }
                    break;

                case SpixiMessageCode.chat:
                    onChat(bytes, message, channel, endpoint);
                    break;

                case SpixiMessageCode.botGetMessages:
                    Messages.sendMessages(endpoint.presence.wallet, channel, spixi_msg.data);
                    break;

                case SpixiMessageCode.msgReceived:
                    {
                        // don't send confirmation back, so just return
                        return;
                    }

                case SpixiMessageCode.msgRead:
                    {
                        // don't send confirmation back, so just return
                        return;
                    }

                case SpixiMessageCode.botAction:
                    onBotAction(spixi_msg.data, endpoint);
                    break;

                case SpixiMessageCode.msgDelete:
                    onMsgDelete(spixi_msg.data, channel, endpoint);
                    break;

                case SpixiMessageCode.msgReaction:
                    onMsgReaction(message, spixi_msg.data, channel, endpoint);
                    break;

                case SpixiMessageCode.leave:
                    onLeave(message.sender);

                    break;

                default:
                    Logging.warn("Received message type that isn't handled {0}", spixi_msg.type);
                    break;
            }

            // TODO: commented for development purposes ONLY!
            /*
                        // Extract the transaction
                        Transaction transaction = new Transaction(message.transaction);

                        // Validate transaction sender
                        if(transaction.from.SequenceEqual(message.sender) == false)
                        {
                            Logging.error(string.Format("Relayed message transaction mismatch for {0}", endpoint_wallet_string));
                            sendError(message.sender);
                            return;
                        }

                        // Validate transaction amount and fee
                        if(transaction.amount < CoreConfig.relayPriceInitial || transaction.fee < CoreConfig.transactionPrice)
                        {
                            Logging.error(string.Format("Relayed message transaction amount too low for {0}", endpoint_wallet_string));
                            sendError(message.sender);
                            return;
                        }

                        // Validate transaction receiver
                        if (transaction.toList.Keys.First().SequenceEqual(IxianHandler.getWalletStorage().address) == false)
                        {
                            Logging.error("Relayed message transaction receiver is not this S2 node");
                            sendError(message.sender);
                            return;
                        }

                        // Update the recipient dictionary
                        if (dataRelays.ContainsKey(message.recipient))
                        {
                            dataRelays[message.recipient]++;
                            if(dataRelays[message.recipient] > Config.relayDataMessageQuota)
                            {
                                Logging.error(string.Format("Exceeded amount of unpaid data relay messages for {0}", endpoint_wallet_string));
                                sendError(message.sender);
                                return;
                            }
                        }
                        else
                        {
                            dataRelays.Add(message.recipient, 1);
                        }


                        // Store the transaction
                        StreamTransaction streamTransaction = new StreamTransaction();
                        streamTransaction.messageID = message.getID();
                        streamTransaction.transaction = transaction;
                        lock (transactions)
                        {
                            transactions.Add(streamTransaction);
                        }

                        // For testing purposes, allow the S2 node to receive relay data itself
                        if (message.recipient.SequenceEqual(IxianHandler.getWalletStorage().getWalletAddress()))
                        {               
                            string test = Encoding.UTF8.GetString(message.data);
                            Logging.info(test);

                            return;
                        }

                        Logging.info("NET: Forwarding S2 data");
                        NetworkStreamServer.forwardMessage(message.recipient, DLT.Network.ProtocolMessageCode.s2data, bytes);      
                        */
        }

        private static void sendReceivedConfirmation(Address recipientAddress, byte[] messageId, int channel, RemoteEndpoint endpoint)
        {
            // Send received confirmation
            StreamMessage msg_received = new StreamMessage();
            msg_received.type = StreamMessageCode.info;
            msg_received.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            msg_received.recipient = recipientAddress;
            msg_received.data = new SpixiMessage(SpixiMessageCode.msgReceived, messageId, channel).getBytes();
            msg_received.encryptionType = StreamMessageEncryptionCode.none;

            sendMessage(endpoint.presence.wallet, msg_received);
        }

        public static void onLeave(Address sender)
        {
            if (Node.users.hasUser(sender))
            {
                var user = Node.users.getUser(sender);
                user.status = BotContactStatus.left;
                Node.users.writeContactsToFile();

                StreamMessage sm = new StreamMessage();
                sm.type = StreamMessageCode.info;
                sm.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
                sm.recipient = sender;
                sm.data = new SpixiMessage(SpixiMessageCode.leaveConfirmed, null).getBytes();
                sm.encryptionType = StreamMessageEncryptionCode.none;

                sendMessage(sender, sm);
            }
        }

        public static void onMsgDelete(byte[] msg_id, int channel, RemoteEndpoint endpoint)
        {
            StreamMessage msg = Messages.getMessage(msg_id, channel);
            if (msg == null)
            {
                return;
            }

            if (isAdmin(endpoint.presence.wallet) || msg.sender.SequenceEqual(endpoint.presence.wallet))
            {
                Messages.removeMessage(msg_id, channel);

                SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.msgDelete, msg_id, channel);

                StreamMessage message = new StreamMessage();
                message.type = StreamMessageCode.info;
                message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
                message.recipient = message.sender;
                message.data = spixi_message.getBytes();
                message.encryptionType = StreamMessageEncryptionCode.none;

                message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());

                Messages.addMessage(message, channel, false);

                NetworkServer.forwardMessage(ProtocolMessageCode.s2data, message.getBytes());
            }
        }

        public static void onMsgReaction(StreamMessage reaction_msg, byte[] msg_reaction_data, int channel, RemoteEndpoint endpoint)
        {
            SpixiMessageReaction smr = new SpixiMessageReaction(msg_reaction_data);
            StreamMessage msg = Messages.getMessage(smr.msgId, channel);
            if (msg == null)
            {
                return;
            }

            Messages.addMessage(reaction_msg, channel, false);
            NetworkServer.forwardMessage(ProtocolMessageCode.s2data, reaction_msg.getBytes());
        }

        public static bool isAdmin(Address contact_address)
        {
            int default_group = Int32.Parse(Node.settings.getOption("defaultGroup", "0"));

            int role_index = Node.users.getUser(contact_address).getPrimaryRole();
            BotGroup group;
            if (Node.groups.groupIndexToName(role_index) != "")
            {
                group = Node.groups.getGroup(Node.groups.groupIndexToName(role_index));
            }
            else
            {
                group = Node.groups.getGroup(Node.groups.groupIndexToName(default_group));
            }
            return group.admin;
        }

        public static IxiNumber getMessagePrice(Address contact_address, int msg_len)
        {
            int default_group = Int32.Parse(Node.settings.getOption("defaultGroup", "0"));

            int role_index = Node.users.getUser(contact_address).getPrimaryRole();
            BotGroup group;
            if (Node.groups.groupIndexToName(role_index) != "")
            {
                group = Node.groups.getGroup(Node.groups.groupIndexToName(role_index));
            }
            else
            {
                group = Node.groups.getGroup(Node.groups.groupIndexToName(default_group));
            }
            return group.messageCost * msg_len / 1000;
        }

        public static void onChat(byte[] raw_message, StreamMessage message, int channel, RemoteEndpoint endpoint)
        {
            if(channel == 0)
            {
                return;
            }

            if (!Node.users.hasUser(endpoint.presence.wallet) || Node.users.getUser(endpoint.presence.wallet).nickData == null)
            {
                requestNickname(endpoint.presence.wallet);
                requestAvatar(endpoint.presence.wallet);
            }

            if(message.id == null)
            {
                return;
            }

            if (Messages.getMessage(message.id, channel) != null)
            {
                return;
            }
            IxiNumber price = getMessagePrice(message.sender, message.data.Length);
            if (price > 0)
            {
                // TODO TODO resend payment request after a while
                // TODO TODO remove pending message after a while
                StreamTransactionRequest str = new StreamTransactionRequest(message.id, price);
                if (pendingMessages.Find(x => x.id.SequenceEqual(message.id)) != null)
                {
                    sendBotAction(message.sender, SpixiBotActionCode.getPayment, str.getBytes(), channel);
                    return;
                }
                pendingMessages.Add(message);
                sendBotAction(message.sender, SpixiBotActionCode.getPayment, str.getBytes(), channel);
            }
            else
            {
                Messages.addMessage(message, channel);
                QuotaManager.addActivity(endpoint.presence.wallet, false);
                // Relay certain messages without transaction
                NetworkServer.forwardMessage(ProtocolMessageCode.s2data, raw_message);
            }
        }

        public static void onBotAction(byte[] action_data, RemoteEndpoint endpoint, int channel = 0)
        {
            SpixiBotAction sba = new SpixiBotAction(action_data);
            switch(sba.action)
            {
                case SpixiBotActionCode.getChannels:
                    sendChannels(endpoint);
                    break;

                case SpixiBotActionCode.getInfo:
                    Node.users.setPubKey(endpoint.presence.wallet, endpoint.serverPubKey, false);
                    sendInfo(endpoint.presence.wallet);
                    break;

                case SpixiBotActionCode.getUsers:
                    sendUsers(endpoint);
                    break;

                case SpixiBotActionCode.getUser:
                    sendUser(endpoint.presence.wallet, Node.users.getUser(new Address(sba.data)));
                    break;

                case SpixiBotActionCode.payment:
                    StreamTransaction stream_tx = new StreamTransaction(sba.data);

                    if (!stream_tx.transaction.toList.Keys.First().SequenceEqual(IxianHandler.getWalletStorage().getPrimaryAddress()))
                    {
                        Logging.warn("Received transaction txid " + stream_tx.transaction.id + " from " + endpoint.presence.wallet.ToString() + " that's not for this node.");
                        return;
                    }

                    StreamMessage sm = pendingMessages.Find(x => x.id.SequenceEqual(stream_tx.messageID));
                    if(sm == null)
                    {
                        // TODO TODO TODO send get message request to the client
                        Logging.warn("Received transaction txid " + stream_tx.transaction.id + " from " + endpoint.presence.wallet.ToString() + " but have no message for this transaction.");
                        return;
                    }

                    IxiNumber price = getMessagePrice(sm.sender, sm.data.Length);
                    if (stream_tx.transaction.amount < price)
                    {
                        Logging.warn("Received transaction txid " + stream_tx.transaction.id + " from " + endpoint.presence.wallet.ToString() + " that has lower than expected amount.");
                        return;
                    }

                    // TODO Add relay nodes
                    //CoreProtocolMessage.broadcastProtocolMessage(new char[] { 'M', 'H' }, ProtocolMessageCode.transactionData2, stream_tx.transaction.getBytes(true, true), null);
                    CoreProtocolMessage.broadcastGetTransaction(stream_tx.transaction.id, 0, null, false);
                    PendingTransactions.addPendingLocalTransaction(stream_tx.transaction, null, stream_tx.messageID);
                    break;

                case SpixiBotActionCode.enableNotifications:
                    bool send_notifications = false;
                    if (sba.data[0] == 1)
                    {
                        //send_notifications = true;
                    }
                    Node.users.getUser(endpoint.presence.wallet).sendNotification = send_notifications;
                    Node.users.writeContactsToFile();
                    break;
            }
        }

        public static void confirmMessage(byte[] msg_id)
        {
            // TODO TODO send confirmation to client
            StreamMessage sm = pendingMessages.Find(x => x.id.SequenceEqual(msg_id));
            if (sm != null)
            {
                pendingMessages.Remove(sm);
                Messages.addMessage(sm, new SpixiMessage(sm.data).channel);
                NetworkServer.forwardMessage(ProtocolMessageCode.s2data, sm.getBytes());
            }
        }

        public static void sendBotAction(Address recipient, SpixiBotActionCode action, byte[] data, int channel = 0)
        {
            SpixiBotAction sba = new SpixiBotAction(action, data);

            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.botAction, sba.getBytes(), channel);

            StreamMessage message = new StreamMessage();
            message.type = StreamMessageCode.info;
            message.recipient = recipient;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;

            sendMessage(recipient, message);
        }

        public static void sendChannel(Address recipient, BotChannel bc)
        {
            sendBotAction(recipient, SpixiBotActionCode.channel, bc.getBytes());
        }

        public static void sendChannels(RemoteEndpoint endpoint)
        {
            Dictionary<string, BotChannel> tmp_channels;
            lock (Node.channels.channels)
            {
                tmp_channels = new Dictionary<string, BotChannel>(Node.channels.channels);
            }
            foreach (var item in tmp_channels)
            {
                sendChannel(endpoint.presence.wallet, item.Value);
            }
        }

        public static void sendUser(Address recipient, BotContact bc)
        {
            sendBotAction(recipient, SpixiBotActionCode.user, bc.getBytes(false));
        }

        public static void sendUsers(RemoteEndpoint endpoint)
        {
            Dictionary<Address, BotContact> tmp_contacts;
            lock (Node.users.contacts)
            {
                tmp_contacts = new Dictionary<Address, BotContact>(Node.users.contacts, new AddressComparer());
            }
            foreach (var item in tmp_contacts)
            {
                if(item.Value.status != BotContactStatus.normal)
                {
                    continue;
                }

                sendUser(endpoint.presence.wallet, item.Value);
            }
        }

        public static void sendInfo(Address wallet_address)
        {
            int default_group = Int32.Parse(Node.settings.getOption("defaultGroup", "0"));

            var user = Node.users.getUser(wallet_address);
            bool send_notifications = user.sendNotification;
            int role_index = user.getPrimaryRole();
            BotGroup group;
            if (Node.groups.groupIndexToName(role_index) != "")
            {
                group = Node.groups.getGroup(Node.groups.groupIndexToName(role_index));
            }
            else
            {
                string group_name = Node.groups.groupIndexToName(default_group);
                if (group_name != null)
                {
                    group = Node.groups.getGroup(group_name);
                }else
                {
                    return;
                }
            }
            IxiNumber cost = 0;
            bool admin = false;
            if (group != null)
            {
                cost = group.messageCost;
                if (group.admin)
                {
                    admin = true;
                }
            }
            BotInfo bi = new BotInfo(0, Node.settings.getOption("serverName", "Bot"), Node.settings.getOption("serverDescription", "Bot"), cost, Int32.Parse(Node.settings.getOption("generatedTime", "0")), admin, default_group, Int32.Parse(Node.settings.getOption("defaultChannel", "0")), send_notifications, Node.users.contacts.Count);
            sendBotAction(wallet_address, SpixiBotActionCode.info, bi.getBytes());
        }

        // Sends an error stream message to a recipient
        // TODO: add additional data for error details
        public static void sendError(Address recipient)
        {
            StreamMessage message = new StreamMessage();
            message.type = StreamMessageCode.error;
            message.recipient = recipient;
            message.data = new byte[1];

            NetworkServer.forwardMessage(recipient, ProtocolMessageCode.s2data, message.getBytes());
        }


        // Send an encrypted message using the S2 network
        public static bool sendMessage(Address recipient_address, StreamMessage msg)
        {
            /*byte[] pubkey = null;

            Presence p = PresenceList.getPresenceByAddress(recipient_address);
            if (p != null && p.addresses.Find(x => x.type == 'C') != null)
            {
                pubkey = p.pubkey;
            }
            msg.encrypt(pubkey, null, null);*/
            if(msg.version >= 1)
            {
                msg.requireRcvConfirmation = false;
            }
            NetworkServer.forwardMessage(recipient_address, ProtocolMessageCode.s2data, msg.getBytes());

            return true;

            /*         string pub_k = FriendList.findContactPubkey(msg.recipientAddress);
                     if (pub_k.Length < 1)
                     {
                         Console.WriteLine("Contact {0} not found, adding to offline queue!", msg.recipientAddress);
                         addOfflineMessage(msg);
                         return;
                     }


                     // Create a new IXIAN transaction
                     //  byte[] checksum = Crypto.sha256(encrypted_message);
                     Transaction transaction = new Transaction(0, msg.recipientAddress, IxianHandler.getWalletStorage().address);
                     //  transaction.data = Encoding.UTF8.GetString(checksum);
                     msg.transactionID = transaction.id;
                     //ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.newTransaction, transaction.getBytes());

                     // Add message to the queue
                     messages.Add(msg);

                     // Request a new keypair from the S2 Node
                     if(hostname == null)
                         ProtocolMessage.broadcastProtocolMessage(ProtocolMessageCode.s2generateKeys, Encoding.UTF8.GetBytes(msg.getID()));
                     else
                     {
                         NetworkClientManager.sendData(ProtocolMessageCode.s2generateKeys, Encoding.UTF8.GetBytes(msg.getID()), hostname);
                     }*/
        }

        public static void sendAcceptAdd(Address recipient, byte[] pub_key)
        {
            Node.users.setPubKey(recipient, pub_key, false);
            var user = Node.users.getUser(recipient);
            if (user != null && user.status != BotContactStatus.banned)
            {
                user.status = BotContactStatus.normal;
            }

            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.acceptAddBot, null);

            StreamMessage message = new StreamMessage();
            message.type = StreamMessageCode.info;
            message.recipient = recipient;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 1 };

            message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());

            sendMessage(recipient, message);
        }

        public static void sendNickname(Address recipient, byte[] contact_address_bytes)
        {
            if (contact_address_bytes != null && contact_address_bytes.Length > 1)
            {
                Address contract_address = new Address(contact_address_bytes);

                if (!Node.users.hasUser(contract_address))
                {
                    return;
                }
                byte[] nickData = Node.users.getUser(contract_address).nickData;
                if (nickData != null)
                {
                    sendMessage(recipient, new StreamMessage(nickData));
                }

                return;
            }

            SpixiMessage reply_spixi_message = new SpixiMessage(SpixiMessageCode.nick, Encoding.UTF8.GetBytes(Config.botName));
            Address sender = IxianHandler.getWalletStorage().getPrimaryAddress();

            // Send the nickname message to friend
            StreamMessage reply_message = new StreamMessage();
            reply_message.type = StreamMessageCode.info;
            reply_message.recipient = recipient;
            reply_message.sender = sender;
            reply_message.data = reply_spixi_message.getBytes();
            reply_message.encryptionType = StreamMessageEncryptionCode.none;
            reply_message.id = new byte[] { 5 };

            reply_message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());

            sendMessage(recipient, reply_message);
        }

        public static void sendAvatar(Address recipient, byte[] contact_address_bytes)
        {
            if (contact_address_bytes != null && contact_address_bytes.Length > 1)
            {
                Address contract_address = new Address(contact_address_bytes);
                if (!Node.users.hasUser(contract_address))
                {
                    return;
                }

                string path = Node.users.getAvatarPath(contract_address);
                if(path == null)
                {
                    return;
                }

                byte[] avatar_data = File.ReadAllBytes(path);
                if (avatar_data != null)
                {
                    sendMessage(recipient, new StreamMessage(avatar_data));
                }

                return;
            }

            byte[] avatar_bytes = Node.getAvatarBytes();

            if (avatar_bytes == null)
            {
                return;
            }

            SpixiMessage reply_spixi_message = new SpixiMessage(SpixiMessageCode.avatar, avatar_bytes);
            Address sender = IxianHandler.getWalletStorage().getPrimaryAddress();

            // Send the nickname message to friend
            StreamMessage reply_message = new StreamMessage();
            reply_message.type = StreamMessageCode.info;
            reply_message.recipient = recipient;
            reply_message.sender = sender;
            reply_message.data = reply_spixi_message.getBytes();
            reply_message.encryptionType = StreamMessageEncryptionCode.none;
            reply_message.id = new byte[] { 6 };

            reply_message.sign(IxianHandler.getWalletStorage().getPrimaryPrivateKey());

            sendMessage(recipient, reply_message);
        }

        // Requests the nickname of the sender
        public static void requestNickname(Address recipient)
        {
            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.getNick, new byte[1]);

            StreamMessage message = new StreamMessage();
            message.type = StreamMessageCode.info;
            message.recipient = recipient;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 3 };

            sendMessage(recipient, message);
        }

        // Requests the avatar of the sender
        public static void requestAvatar(Address recipient)
        {
            // Prepare the message and send to the S2 nodes
            SpixiMessage spixi_message = new SpixiMessage(SpixiMessageCode.getAvatar, new byte[1]);

            StreamMessage message = new StreamMessage();
            message.type = StreamMessageCode.info;
            message.recipient = recipient;
            message.sender = IxianHandler.getWalletStorage().getPrimaryAddress();
            message.data = spixi_message.getBytes();
            message.encryptionType = StreamMessageEncryptionCode.none;
            message.id = new byte[] { 4 };

            sendMessage(recipient, message);
        }
    }
}
