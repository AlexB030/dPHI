%script to read in the topology information. Download the caida datasets
%at: https://www.caida.org/data/as-relationships/    
% and https://www.caida.org/data/routing/routeviews-prefix2as.xml 
% We have MANUALLY altered the as-rel.txt by removing the preceeeding lines
% (therefore renamed it :Modified.txt) so that the first line does not
% contain comments but content.
%
%
%We have also modified the .pfx2as files MANUALLY by first importing it
%into Excel and turning it into a csv file with semicolons as delimiter with
%a fixed site. (Sorry but this was a one-time process so we have not
%automated it.) Note that if you use the same dataset as in PETs you do not
%need to repeat this but simply use the .mat files.
%
% We have also included these altered files so that you know how it should look like after your manual tweeking. THe Caida projekt allowed us to include their data into our folder but you have to agree to the CAIDA license to use it and would like you to download the files directly from Caida if you want to use it outside of these scripts
%

clc
clear all
% loading the AS graph without provider customer relationships

use2019=0; % In the paper we use the dataset for 2014, but you can also try with the 2019 data set by setting this to 1
% Of course you have to modify the path manually
if(use2019==1)
    folder='caidaData\'
    filename='20190701.as-rel_Modified'
else
    folder='caidaData\'
    filename='20140901.as-rel_Modified.txt'
end
%folder='D:\svn\nextphi\code\raw_data\caida_as_topology\as_rank\'
%filename='truth-comms.txt'


fileAddress = strcat(folder,filename);
delimiter = '|';
formatSpec = '%d%d%d';
% Open the text file.
fileID = fopen(fileAddress,'r');
dataArray = textscan(fileID, formatSpec, 'Delimiter', delimiter, 'TextType', 'string',  'ReturnOnError', false);
% Close the text file.
fclose(fileID);

%sourceList=convertStringsToChars(dataArray{1});
%destinationList=convertStringsToChars(dataArray{2});

%edgeTable=convertStringsToChars([sourceList destinationList]);
sourceList=dataArray{1};
destinationList=dataArray{2};
edgeTypeList=dataArray{3};

%not for every number an AS exists in the list but it is easier if we give
%the ASes continous numbers. Therefore we use listOfNodes as the
%translation between our internal number and the "real AS number". The AS
%we label as 1 is listed on position i in listOfNodes. The AS labled as 2
%at two and so forth
listOfNodes=unique([sourceList;destinationList]);

% let us replace the names of the ASes with number of
% 1:size(listOfNodes,1);
%tmpNodeslist=1:size(listOfNodes,1);
%listOfNodes=[tmpNodeslist' listOfNodes];

%we now translate the external numbering system into our own internal
%numbering system.
for(i=1:size(sourceList,1))
    sourceList(i)=find(listOfNodes==sourceList(i));
    destinationList(i)=find(listOfNodes==destinationList(i));
end

%differentiate what type of edge this is
sourceListPtoC=sourceList(edgeTypeList==-1);
destinationListPtoC=destinationList(edgeTypeList==-1);

sourceListPtoP=sourceList(edgeTypeList==0);
destinationListPtoP=destinationList(edgeTypeList==0);

numOfNodes=size(listOfNodes,1);

%This is the cell in which we store the edges with our new numbering system
sourceCellC=cell(numOfNodes,1);
sourceCellP=cell(numOfNodes,1);
sourceCellPtoP=cell(numOfNodes,1);
tic
for(i=1:numOfNodes)
    sourceCellC{i}=sourceListPtoC(destinationListPtoC==i);
    sourceCellP{i}=destinationListPtoC(sourceListPtoC==i);
    sourceCellPtoP{i}=[sourceListPtoP(destinationListPtoP==i);destinationListPtoP(sourceListPtoP==i)];
end
toc

if(use2019==1)
    save('nographFrom2019withAll.mat','sourceCellC','sourceCellP','sourceCellPtoP','listOfNodes','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP')
else
    
% For 2014 we also read in the IP address range     
% load the file with the AS to IP addresses:

folder='caidaData\'
filename='routeviews-rv2-20140901-1200_Modified.csv'



fileAddress = strcat(folder,filename);
delimiter = ';';
formatSpec = '%s%d%d%d%d%d%d%d%d%d%d%d%d%d';
% Open the text file.
fileID = fopen(fileAddress,'r');
dataArrayIPs = textscan(fileID, formatSpec, 'Delimiter', delimiter, 'TextType', 'string',  'ReturnOnError', false);
% Close the text file.
fclose(fileID);

listIpsPerAS=zeros(size(listOfNodes,1),1);
ipRanges=double(dataArrayIPs{2});
correspondingAS=dataArrayIPs{3};
for(i=1:size(ipRanges,1))
    ASnumber=find(listOfNodes==correspondingAS(i));
    listIpsPerAS(ASnumber)=listIpsPerAS(ASnumber)+2^(32-ipRanges(i));
end
    save('nographFrom2014withAll.mat','sourceCellC','sourceCellP','sourceCellPtoP','listOfNodes','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP','listIpsPerAS')
end



% 
% G=digraph(sourceList,destinationList);
% GPtoP=G;
% G=G.rmedge(sourceList(edgeTypeList==0),destinationList(edgeTypeList==0));
% %G=G.addedge(destinationList(edgeTypeList==0),sourceList(edgeTypeList==0));
% %G=G.addedge(destinationList(edgeTypeList==-1),sourceList(edgeTypeList==-1));
% GPtoP=GPtoP.rmedge(sourceList(edgeTypeList==-1),destinationList(edgeTypeList==-1));
% 

