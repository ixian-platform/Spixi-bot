﻿using IXICore;
using IXICore.Inventory;
using IXICore.Meta;
using IXICore.Network;
using IXICore.Network.Messages;
using IXICore.Utils;
using SpixiBot.Meta;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Threading;

namespace SpixiBot.Network
{
    public class ProtocolMessage
    {
        // Unified protocol message parsing
        public static void parseProtocolMessage(ProtocolMessageCode code, byte[] data, RemoteEndpoint endpoint)
        {
            if (endpoint == null)
            {
                Logging.error("Endpoint was null. parseProtocolMessage");
                return;
            }
            try
            {
                switch (code)
                {
                    case ProtocolMessageCode.hello:
                        using (MemoryStream m = new MemoryStream(data))
                        {
                            using (BinaryReader reader = new BinaryReader(m))
                            {
                                bool processed = false;
                                processed = CoreProtocolMessage.processHelloMessageV6(endpoint, reader, false);

                                 if (!processed || (Config.whiteList.Count > 0 && !Config.whiteList.Contains(endpoint.presence.wallet, new AddressComparer())))
                                {
                                    CoreProtocolMessage.sendBye(endpoint, ProtocolByeCode.bye, string.Format("Access denied."), "", true);
                                    return;
                                }

                                endpoint.helloReceived = true;
                            }
                        }
                        break;


                    case ProtocolMessageCode.helloData:
                        using (MemoryStream m = new MemoryStream(data))
                        {
                            using (BinaryReader reader = new BinaryReader(m))
                            {
                                if (CoreProtocolMessage.processHelloMessageV6(endpoint, reader))
                                {
                                    char node_type = endpoint.presenceAddress.type;
                                    if (node_type != 'M' && node_type != 'H' && node_type != 'R')
                                    {
                                        CoreProtocolMessage.sendBye(endpoint, ProtocolByeCode.expectingMaster, string.Format("Expecting master node."), "", true);
                                        return;
                                    }

                                    ulong last_block_num = reader.ReadIxiVarUInt();

                                    int bcLen = (int)reader.ReadIxiVarUInt();
                                    byte[] block_checksum = reader.ReadBytes(bcLen);

                                    endpoint.blockHeight = last_block_num;

                                    int block_version = (int)reader.ReadIxiVarUInt();

                                    try
                                    {
                                        string public_ip = reader.ReadString();
                                        ((NetworkClient)endpoint).myAddress = public_ip;
                                    }
                                    catch (Exception)
                                    {

                                    }

                                    // Process the hello data
                                    endpoint.helloReceived = true;
                                    NetworkClientManager.recalculateLocalTimeDifference();

                                    if (node_type == 'R')
                                    {
                                        string[] connected_servers = NetworkClientManager.getConnectedClients(true);
                                        if (connected_servers.Count() == 1
                                            || IxianHandler.publicIP == "")
                                        {
                                            string address = Node.networkClientManagerStatic.getMyAddress();
                                            if (address != null)
                                            {
                                                if (IxianHandler.publicIP != address)
                                                {
                                                    Logging.info("Setting public IP to " + address);
                                                    IxianHandler.publicIP = address;
                                                    PresenceList.forceSendKeepAlive = true;
                                                    Logging.info("Forcing KA from networkprotocol");
                                                }
                                            }
                                        }
                                        else
                                        {
                                            // Announce local presence
                                            var myPresence = PresenceList.curNodePresence;
                                            if (myPresence != null)
                                            {
                                                foreach (var pa in myPresence.addresses)
                                                {
                                                    byte[] hash = CryptoManager.lib.sha3_512sqTrunc(pa.getBytes());
                                                    var iika = new InventoryItemKeepAlive(hash, pa.lastSeenTime, myPresence.wallet, pa.device);
                                                    endpoint.addInventoryItem(iika);
                                                }
                                            }
                                        }
                                    }

                                    if (node_type == 'M'
                                        || node_type == 'H'
                                        || node_type == 'R')
                                    {
                                        CoreProtocolMessage.subscribeToEvents(endpoint);
                                    }
                                }
                            }
                        }
                        break;

                    case ProtocolMessageCode.s2data:
                        {
                            StreamProcessor.receiveData(data, endpoint);
                        }
                        break;

                    case ProtocolMessageCode.s2failed:
                        {
                            using (MemoryStream m = new MemoryStream(data))
                            {
                                using (BinaryReader reader = new BinaryReader(m))
                                {
                                    Logging.error("Failed to send s2 data");
                                }
                            }
                        }
                        break;

                    case ProtocolMessageCode.getPresence2:
                        {
                            using (MemoryStream m = new MemoryStream(data))
                            {
                                using (BinaryReader reader = new BinaryReader(m))
                                {
                                    int walletLen = (int)reader.ReadIxiVarUInt();
                                    Address wallet = new Address(reader.ReadBytes(walletLen));

                                    Presence p = PresenceList.getPresenceByAddress(wallet);
                                    if (p != null)
                                    {
                                        lock (p)
                                        {
                                            byte[][] presence_chunks = p.getByteChunks();
                                            foreach (byte[] presence_chunk in presence_chunks)
                                            {
                                                endpoint.sendData(ProtocolMessageCode.updatePresence, presence_chunk, null);
                                            }
                                        }
                                    }
                                    else
                                    {
                                        // TODO blacklisting point
                                        Logging.warn(string.Format("Node has requested presence information about {0} that is not in our PL.", wallet.ToString()));
                                    }
                                }
                            }
                        }
                        break;

                    case ProtocolMessageCode.balance2:
                        {
                            using (MemoryStream m = new MemoryStream(data))
                            {
                                using (BinaryReader reader = new BinaryReader(m))
                                {
                                    int address_length = (int)reader.ReadIxiVarUInt();
                                    Address address = new Address(reader.ReadBytes(address_length));

                                    int balance_bytes_len = (int)reader.ReadIxiVarUInt();
                                    byte[] balance_bytes = reader.ReadBytes(balance_bytes_len);

                                    // Retrieve the latest balance
                                    IxiNumber ixi_balance = new IxiNumber(new BigInteger(balance_bytes));

                                    // Retrieve the blockheight for the balance
                                    ulong block_height = reader.ReadIxiVarUInt();
                                    byte[] block_checksum = reader.ReadBytes((int)reader.ReadIxiVarUInt());

                                    foreach (Balance balance in IxianHandler.balances)
                                    {
                                        if (address.addressNoChecksum.SequenceEqual(balance.address.addressNoChecksum))
                                        {

                                            if (block_height > balance.blockHeight && (balance.balance != ixi_balance || balance.blockHeight == 0))
                                            {
                                                balance.address = address;
                                                balance.balance = ixi_balance;
                                                balance.blockHeight = block_height;
                                                balance.blockChecksum = block_checksum;
                                                balance.verified = false;
                                            }

                                            balance.lastUpdate = Clock.getTimestamp();
                                        }
                                    }
                                }
                            }
                        }
                        break;


                    case ProtocolMessageCode.updatePresence:
                        handleUpdatePresence(data, endpoint);
                        break;

                    case ProtocolMessageCode.keepAlivePresence:
                        handleKeepAlivePresence(data, endpoint);
                        break;

                    case ProtocolMessageCode.compactBlockHeaders1:
                        {
                            using (MemoryStream m = new MemoryStream(data))
                            {
                                using (BinaryReader reader = new BinaryReader(m))
                                {
                                    ulong from = reader.ReadIxiVarUInt();
                                    ulong totalCount = reader.ReadIxiVarUInt();

                                    int filterLen = (int)reader.ReadIxiVarUInt();
                                    byte[] filterBytes = reader.ReadBytes(filterLen);

                                    byte[] headersBytes = new byte[reader.BaseStream.Length - reader.BaseStream.Position];
                                    Array.Copy(data, reader.BaseStream.Position, headersBytes, 0, headersBytes.Length);

                                    Node.tiv.receivedBlockHeaders3(headersBytes, endpoint);
                                }
                            }
                        }
                        break;

                    case ProtocolMessageCode.blockHeaders3:
                        {
                            // Forward the block headers to the TIV handler
                            Node.tiv.receivedBlockHeaders3(data, endpoint);
                        }
                        break;

                    case ProtocolMessageCode.pitData2:
                        {
                            Node.tiv.receivedPIT2(data, endpoint);
                        }
                        break;

                    case ProtocolMessageCode.transactionData2:
                        handleTransactionData(data, endpoint);
                        break;

                    case ProtocolMessageCode.bye:
                        CoreProtocolMessage.processBye(data, endpoint);
                        break;

                    case ProtocolMessageCode.inventory2:
                        handleInventory2(data, endpoint);
                        break;

                    case ProtocolMessageCode.sectorNodes:
                        handleSectorNodes(data, endpoint);
                        break;

                    case ProtocolMessageCode.nameRecord:
                        handleNameRecord(data, endpoint);
                        break;

                    case ProtocolMessageCode.keepAlivesChunk:
                        handleKeepAlivesChunk(data, endpoint);
                        break;

                    case ProtocolMessageCode.rejected:
                        handleRejected(data, endpoint);
                        break;

                    case ProtocolMessageCode.getKeepAlives:
                        CoreProtocolMessage.processGetKeepAlives(data, endpoint);
                        break;

                    default:
                        Logging.warn("Unknown protocol message: {0}, from {1} ({2})", code, endpoint.getFullAddress(), endpoint.serverWalletAddress);
                        break;

                }
            }
            catch (Exception e)
            {
                Logging.error(string.Format("Error parsing network message. Details: {0}", e.ToString()));
            }
        }

        static void handleTransactionData(byte[] data, RemoteEndpoint endpoint)
        {
            Transaction tx = new Transaction(data, true, true);

            if (endpoint.presenceAddress.type == 'M' || endpoint.presenceAddress.type == 'H')
            {
                PendingTransactions.increaseReceivedCount(tx.id, endpoint.presence.wallet);
            }

            Node.tiv.receivedNewTransaction(tx);
            Logging.info("Received new transaction {0}", tx.id);

            Node.addTransactionToActivityStorage(tx);
        }


        public static void handleKeepAlivesChunk(byte[] data, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    int ka_count = (int)reader.ReadIxiVarUInt();

                    int max_ka_per_chunk = CoreConfig.maximumKeepAlivesPerChunk;
                    if (ka_count > max_ka_per_chunk)
                    {
                        ka_count = max_ka_per_chunk;
                    }

                    for (int i = 0; i < ka_count; i++)
                    {
                        if (m.Position == m.Length)
                        {
                            break;
                        }

                        int ka_len = (int)reader.ReadIxiVarUInt();
                        byte[] ka_bytes = reader.ReadBytes(ka_len);

                        handleKeepAlivePresence(ka_bytes, endpoint);
                    }
                }
            }
        }

        static void handleUpdatePresence(byte[] data, RemoteEndpoint endpoint)
        {

            // Parse the data and update entries in the presence list
            Presence p = PresenceList.updateFromBytes(data, 0);
            if (p == null)
            {
                Logging.warn("Received invalid presence list update");
                return;
            }

            Logging.info("Received presence update for " + p.wallet);
        }

        static void handleKeepAlivePresence(byte[] data, RemoteEndpoint endpoint)
        {
            byte[] hash = CryptoManager.lib.sha3_512sqTrunc(data);

            InventoryCache.Instance.setProcessedFlag(InventoryItemTypes.keepAlive, hash, true);

            Address address = null;
            long last_seen = 0;
            byte[] device_id = null;
            char node_type;
            bool updated = PresenceList.receiveKeepAlive(data, out address, out last_seen, out device_id, out node_type, endpoint);

            Logging.trace("Received keepalive update for " + address);
        }


        static void handleInventory2(byte[] data, RemoteEndpoint endpoint)
        {
            using (MemoryStream m = new MemoryStream(data))
            {
                using (BinaryReader reader = new BinaryReader(m))
                {
                    ulong item_count = reader.ReadIxiVarUInt();
                    if (item_count > (ulong)CoreConfig.maxInventoryItems)
                    {
                        Logging.warn("Received {0} inventory items, max items is {1}", item_count, CoreConfig.maxInventoryItems);
                        item_count = (ulong)CoreConfig.maxInventoryItems;
                    }

                    ulong last_accepted_block_height = IxianHandler.getLastBlockHeight();

                    ulong network_block_height = IxianHandler.getHighestKnownNetworkBlockHeight();

                    Dictionary<ulong, List<InventoryItemSignature>> sig_lists = new Dictionary<ulong, List<InventoryItemSignature>>();
                    List<InventoryItemKeepAlive> ka_list = new List<InventoryItemKeepAlive>();
                    List<byte[]> tx_list = new List<byte[]>();
                    for (ulong i = 0; i < item_count; i++)
                    {
                        ulong len = reader.ReadIxiVarUInt();
                        byte[] item_bytes = reader.ReadBytes((int)len);
                        InventoryItem item = InventoryCache.decodeInventoryItem(item_bytes);
                        if (item.type == InventoryItemTypes.transaction)
                        {
                            PendingTransactions.increaseReceivedCount(item.hash, endpoint.presence.wallet);
                        }
                        PendingInventoryItem pii = InventoryCache.Instance.add(item, endpoint);

                        // First update endpoint blockheights
                        switch (item.type)
                        {
                            case InventoryItemTypes.block:
                                var iib = ((InventoryItemBlock)item);
                                if (iib.blockNum > endpoint.blockHeight)
                                {
                                    endpoint.blockHeight = iib.blockNum;
                                }
                                break;
                        }

                        if (!pii.processed && pii.lastRequested == 0)
                        {
                            // first time we're seeing this inventory item
                            switch (item.type)
                            {
                                case InventoryItemTypes.keepAlive:
                                    var iika = (InventoryItemKeepAlive)item;
                                    if (PresenceList.getPresenceByAddress(iika.address) != null)
                                    {
                                        ka_list.Add(iika);
                                        pii.lastRequested = Clock.getTimestamp();
                                    }
                                    else
                                    {
                                        InventoryCache.Instance.processInventoryItem(pii);
                                    }
                                    break;

                                case InventoryItemTypes.transaction:
                                    tx_list.Add(item.hash);
                                    pii.lastRequested = Clock.getTimestamp();
                                    break;

                                case InventoryItemTypes.block:
                                    var iib = ((InventoryItemBlock)item);
                                    if (iib.blockNum <= last_accepted_block_height)
                                    {
                                        InventoryCache.Instance.setProcessedFlag(iib.type, iib.hash, true);
                                        continue;
                                    }

                                    var netBlockNum = CoreProtocolMessage.determineHighestNetworkBlockNum();
                                    if (iib.blockNum > netBlockNum)
                                    {
                                        continue;
                                    }

                                    requestNextBlock(iib.blockNum, iib.hash, endpoint);
                                    break;

                                default:
                                    Logging.warn("Unhandled inventory item {0}", item.type);
                                    break;
                            }
                        }
                    }

                    CoreProtocolMessage.broadcastGetKeepAlives(ka_list, endpoint);

                    CoreProtocolMessage.broadcastGetTransactions(tx_list, 0, endpoint);
                }
            }
        }

        static void requestNextBlock(ulong blockNum, byte[] blockHash, RemoteEndpoint endpoint)
        {
            InventoryItemBlock iib = new InventoryItemBlock(blockHash, blockNum);
            PendingInventoryItem pii = InventoryCache.Instance.add(iib, endpoint);
            if (!pii.processed
                && pii.lastRequested == 0)
            {
                pii.lastRequested = Clock.getTimestamp();
                InventoryCache.Instance.processInventoryItem(pii);
            }
        }

        static void handleNameRecord(byte[] data, RemoteEndpoint endpoint)
        {
            int offset = 0;

            var nameAndOffset = data.ReadIxiBytes(offset);
            offset += nameAndOffset.bytesRead;
            byte[] name = nameAndOffset.bytes;

            var recordCountAndOffset = data.GetIxiVarUInt(offset);
            offset += recordCountAndOffset.bytesRead;
            int recordCount = (int)recordCountAndOffset.num;

            for (int i = 0; i < recordCount; i++)
            {
                var recordAndOffset = data.ReadIxiBytes(offset);
                offset += recordAndOffset.bytesRead;
            }
        }


        static void handleSectorNodes(byte[] data, RemoteEndpoint endpoint)
        {
            int offset = 0;

            var prefixAndOffset = data.ReadIxiBytes(offset);
            offset += prefixAndOffset.bytesRead;
            byte[] prefix = prefixAndOffset.bytes;

            var nodeCountAndOffset = data.GetIxiVarUInt(offset);
            offset += nodeCountAndOffset.bytesRead;
            int nodeCount = (int)nodeCountAndOffset.num;

            for (int i = 0; i < nodeCount; i++)
            {
                var kaBytesAndOffset = data.ReadIxiBytes(offset);
                offset += kaBytesAndOffset.bytesRead;

                Presence p = PresenceList.updateFromBytes(kaBytesAndOffset.bytes, IxianHandler.getMinSignerPowDifficulty(IxianHandler.getLastBlockHeight() + 1, IxianHandler.getLastBlockVersion(), Clock.getNetworkTimestamp()));
                if (p != null)
                {
                    RelaySectors.Instance.addRelayNode(p.wallet);
                }
            }

            List<Peer> peers = new();
            var relays = RelaySectors.Instance.getSectorNodes(prefix, CoreConfig.maxRelaySectorNodesToRequest);
            foreach (var relay in relays)
            {
                var p = PresenceList.getPresenceByAddress(relay);
                if (p == null)
                {
                    continue;
                }
                var pa = p.addresses.First();
                peers.Add(new(pa.address, relay, pa.lastSeenTime, 0, 0, 0));

                PeerStorage.addPeerToPeerList(pa.address, p.wallet, pa.lastSeenTime, 0, 0, 0);
            }

            if (IxianHandler.primaryWalletAddress.sectorPrefix.SequenceEqual(prefix))
            {
                Node.networkClientManagerStatic.setClientsToConnectTo(peers);
            }
        }

        static void handleRejected(byte[] data, RemoteEndpoint endpoint)
        {
            try
            {
                Rejected rej = new Rejected(data);
                switch (rej.code)
                {
                    case RejectedCode.TransactionInvalid:
                    case RejectedCode.TransactionInsufficientFee:
                    case RejectedCode.TransactionDust:
                        Logging.error("Transaction {0} was rejected with code: {1}", Crypto.hashToString(rej.data), rej.code);
                        PendingTransactions.remove(rej.data);
                        // TODO flag transaction as invalid
                        break;

                    case RejectedCode.TransactionDuplicate:
                        Logging.warn("Transaction {0} already sent.", Crypto.hashToString(rej.data), rej.code);
                        // All good
                        PendingTransactions.increaseReceivedCount(rej.data, endpoint.serverWalletAddress);
                        break;

                    default:
                        Logging.error("Received 'rejected' message with unknown code {0} {1}", rej.code, Crypto.hashToString(rej.data));
                        break;
                }
            }
            catch (Exception e)
            {
                throw new Exception(string.Format("Exception occured while processing 'rejected' message with code {0} {1}", data[0], Crypto.hashToString(data)), e);
            }
        }

    }
}