public class DataLimiter
{
    internal readonly int MaxDataSize;

    public DataLimiter(int maxDataSize)
    {
        MaxDataSize = maxDataSize;
    }

    public bool IsLimitExceeded(int receivedDataSize)
    {
        return receivedDataSize > MaxDataSize;
    }
}