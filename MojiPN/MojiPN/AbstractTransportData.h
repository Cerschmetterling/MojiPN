class AbstractTransportData{
private:
	unsigned short source_port;
	unsigned short dest_port;
	unsigned short checksum;
	virtual unsigned char*  buildHeader();
public:
	
	unsigned short getSourcePort(){
		return source_port;
	}
	unsigned short getDestPort(){
		return dest_port;
	}
	unsigned short getChecksum(){
		return checksum;
	}
	void setSourcePort(unsigned short sp){
		this->source_port = sp;
	}
	void setDestPort(unsigned short dp){
		this->dest_port = dp;
	}
	unsigned char* getRawHeader(){
		return buildHeader();
	}
	virtual void calcChecksum();
	

	

};