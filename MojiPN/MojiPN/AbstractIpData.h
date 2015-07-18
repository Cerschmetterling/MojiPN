class AbstractIpData{
private:
	unsigned int version;

	virtual unsigned char* buildHeader();
public:	
	
	unsigned int getVersion(){
		return this->version;
	}
	void setVersion(unsigned int v){
		this->version = v;
	}
	virtual unsigned char* getRawHeader(){
		return buildHeader();
	}
};