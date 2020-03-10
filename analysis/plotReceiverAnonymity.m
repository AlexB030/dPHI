
% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

%% Plotting sender anonymity figures.

clear all
clc
plotWithIP=1;
saveFigures=0;
plotRes4=0 % When set to 1 to get Figure 5 f with all distances and all protocols and set to 0 to plot s to w for PHI and dPHI (figure 5 e) 

if(plotWithIP==1)
    fileEnding='IP.mat';
    figureEnding='IP';
else
    fileEnding='NoIP.mat';
    figureEnding='NoIP';
end

%%Plot destination anonymity
      
% for PHI and dPHI the destination anonymity for nodes on path w to
% d is 1, as the destination is not hidden. Just computing
% destination anonymity for HORNET for all nodes is an unfair without considering these nodes as well.

%We therefore have to explicitly set the destination anonymity for
%w to d to one.
load(['sourceAnonymityWtoDforstored1000' fileEnding],'anonymitySetsizePHIAll');
anonymitySetsizePHIAll=anonymitySetsizePHIAll>0.1;

destinationAnonymityDPHI=zeros(2000,5);
destinationAnonymityPHI=zeros(2000,5);
destinationAnonymityDPHI(1:1000,1:5)=anonymitySetsizePHIAll;
destinationAnonymityPHI(1:1000,1:5)=anonymitySetsizePHIAll;
load('destinationAnonymityStoWforstored1000IP','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll');
destinationAnonymityDPHI(1001:2000,1:3)=anonymitySetsizeDPHIAll;
destinationAnonymityPHI(1001:2000,1:3)=anonymitySetsizePHIAll;

% Now load HORNET
load('destinationeAnonymityHornet1000IP.mat','anonymitySetsizeHorAll','anonymitySetsizeHorSingle')
%The exit node is not included in the above analysis, but is
%included in LAP and PHI, hence it is only fair to also include the
%exit node which knows the client.
anonymitySetsizeHorAll(:,2:end)=anonymitySetsizeHorAll(:,1:end-1);
anonymitySetsizeHorAll(:,1)=1;

%in LAP, the distance is known
anonymitySetsizeLAPAll=ones(size(anonymitySetsizePHIAll,1),size(anonymitySetsizePHIAll,2)); 
if(plotRes4)
    titleFirst="CDF of receiver anonymity set size";
    titleSecond="(all nodes, including exit node)";
    fileName="figureplotDestinationAnonymityAllIP";
    resultList={destinationAnonymityPHI,destinationAnonymityDPHI,anonymitySetsizeLAPAll,anonymitySetsizeHorAll};
    experimentNames={"PHI","dPHI","LAP","HORNET"};
    numOfResults=4;
else
    titleFirst="CDF of receiver anonymity set size";
    titleSecond="for nodes on path s to W";
    fileName="figureplotDestinationAnonymityStoWIP";
    resultList={anonymitySetsizePHIAll,anonymitySetsizeDPHIAll};
    experimentNames={"PHI","dPHI",};
    numOfResults=2;
end

plotCDFComparison(resultList,numOfResults,experimentNames,titleFirst,titleSecond,plotWithIP,saveFigures,fileName,1,0)

  %% Now plot sender-receiver anonymity (or rather its upper bound)

if(plotWithIP)
    load('sourceDestinationAnonymityIP','sourceAndDestinationAnonymityDPHI','sourceAndDestinationAnonymityPHI','sourceAndDestinationAnonymityHor')
    load('sourceAnonymityVSSwithM2forstored1000IP.mat','chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSS','anonymitySetsizeVSSSingle')    
    load('sourceAnonymityVSSwithM3forstored1000IP.mat','chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSSM3','anonymitySetsizeVSSSingleM3')

    resultList={sourceAndDestinationAnonymityPHI,sourceAndDestinationAnonymityDPHI,anonymitySetsizeLAP,anonymitySetsizeVSSM3,sourceAndDestinationAnonymityHor};
    titleFirst="Upper bound of Sender-Receiver Anonymity";
    titleSecond="";
    experimentNames={"PHI","dPHI","LAP (no VSS)","LAP (VSS=3)", "HORNET"};
    numOfResults=5;
    isIP=4; %it is source and destination hence we need axis to go to 2^64
    fileName="figureplotSourceAndDestinationIP";
    plotCDFComparison(resultList,numOfResults,experimentNames,titleFirst,titleSecond,isIP,saveFigures,fileName,1,0) 
end
  