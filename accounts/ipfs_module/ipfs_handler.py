import ipfshttpclient,os,logging
from pathlib import Path

logger = logging.getLogger(__name__)

class IPFSHandler:
    def __init__(self, ipfs_url = "/ip4/127.0.0.1/tcp/5001"): #multiformat url
        self.client = ipfshttpclient.connect(ipfs_url)
        print("connected to ipfs")
    
    def upload_file(self, file_path):
        result = self.client.add(file_path)

        #for directory uploads
        if isinstance(result, list):
            return result[-1]['Hash']
        
        #for file uploads
        return result['Hash'] #CID
    
    def get_file(self, cid):
        
        return self.client.cat(cid)
        """ try:
            output_path = Path(output_path)  # Ensure Path object
            # Ensure output directory exists
            os.makedirs(output_path.parent, exist_ok=True)
            logger.info(f"Attempting to download CID {cid} to {output_path}")
            # Download file from IPFS
            self.client.get(cid, str(output_path))
            # Verify file exists
            if not output_path.exists():
                logger.error(f"File {output_path} was not created after IPFS get")
                raise Exception(f"Failed to download file for CID {cid}")
            # Check file size to ensure it's not empty or just CID
            file_size = output_path.stat().st_size
            if file_size < 100:  # Arbitrary threshold for small files
                with open(output_path, 'rb') as f:
                    content = f.read().decode('utf-8', errors='ignore').strip()
                    if content == cid:
                        logger.error(f"Downloaded file contains CID {cid} instead of content")
                        raise Exception(f"Downloaded file contains CID instead of content")
            # Set file permissions
            os.chmod(output_path, 0o666)
            logger.info(f"Successfully downloaded file to {output_path}")
        except Exception as e:
            logger.error(f"Failed to retrieve file for CID {cid}: {str(e)}")
            raise Exception(f"Failed to retrieve file from IPFS: {str(e)}") """
        """ try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            self.client.get(cid, target=output_path)
            print(f"saved to {output_path}")
        except Exception as e:
            raise Exception(f"Failed to retrieve file from IPFS: {str(e)}") """
