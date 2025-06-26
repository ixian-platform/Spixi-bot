using IXICore;
using IXICore.Meta;
using SpixiBot.Network;
using System;
using System.Linq;

namespace SpixiBot.Meta
{
    internal class SpixiBotTransactionInclusionCallbacks : TransactionInclusionCallbacks
    {
        public void receivedTIVResponse(byte[] txid, bool verified)
        {
            // TODO implement error
            // TODO implement blocknum

            ActivityStatus status = ActivityStatus.Pending;
            if (verified)
            {
                status = ActivityStatus.Final;
                PendingTransaction p_tx = PendingTransactions.getPendingTransaction(txid);
                if (p_tx != null)
                {
                    if (p_tx.messageId != null)
                    {
                        StreamProcessor.confirmMessage(p_tx.messageId);
                    }
                    PendingTransactions.remove(txid);
                }
            }

            ActivityStorage.updateStatus(txid, status, 0);
        }

        public void receivedBlockHeader(Block block_header, bool verified)
        {
            foreach (Balance balance in IxianHandler.balances)
            {
                if (balance.blockChecksum != null && balance.blockChecksum.SequenceEqual(block_header.blockChecksum))
                {
                    balance.verified = true;
                }
            }

            if (block_header.blockNum >= IxianHandler.getHighestKnownNetworkBlockHeight())
            {
                IxianHandler.status = NodeStatus.ready;
            }
            Node.processPendingTransactions();
        }
    }
}
