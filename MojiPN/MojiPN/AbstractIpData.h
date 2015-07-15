class AbstractIpData{
private:
	unsigned int version;
public:	
	virtual void buildHeader();
	unsigned int getVersion(){
		return version;
	}


};