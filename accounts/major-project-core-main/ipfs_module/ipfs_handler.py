import ipfshttpclient

class IPFSHandler:
    def __init__(self, ipfs_url = "/ip4/127.0.0.1/tcp/5001"): #multiformat url
        self.client = ipfshttpclient.connect(ipfs_url)
        print("connected to ipfs")
    
    def upload_file(self, file_path):
        result = self.client.add(file_path)
        
        # print("result = ", result)

        #for directory uploads
        if isinstance(result, list):
            return result[-1]['Hash']
        
        #for file uploads
        return result['Hash'] #CID
    
    def get_file(self, cid, output_path):
        self.client.get(cid, target=output_path)
        print(f"saved to {output_path}")

