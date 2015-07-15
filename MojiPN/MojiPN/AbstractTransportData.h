class AbstractTransportData{
private:
	unsigned short source_port;
	unsigned short dest_port;
	unsigned short checksum;
public:
	
	unsigned short getSourcePort(){
		return source_port;
	}
	unsigned short getDestPort(){
		return dest_port;
	}
	unsigned short getChecksum();
	virtual void calcChecksum();
	virtual void buildHeader();

};