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

if(plotWithIP==1)
    fileEnding='IP.mat';
    figureEnding='IP';
else
    fileEnding='NoIP.mat';
    figureEnding='NoIP';
end


%% Loading in all sender anonymity values. Since the variables are not named intuitvely, rename them.
%load LAP
load(['sourceAnonymityVSSwithM2forstored1000' fileEnding],'chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSS','anonymitySetsizeVSSSingle')    
load(['sourceAnonymityVSSwithM3forstored1000' fileEnding],'chosenM','anonymitySetsizeLAP','anonymitySetsizeLAPNoLength','anonymitySetsizeLAPSingle','anonymitySetsizeLAPNoLengthSingle','anonymitySetsizeVSSM3','anonymitySetsizeVSSSingleM3')
senderAnonymityLAP=anonymitySetsizeLAP;
senderAnonymityLAP2=anonymitySetsizeVSS;
senderAnonymityLAP3=anonymitySetsizeVSSM3;

%source Anonymity Hornet
load(['sourceAnonymityHornet1000' fileEnding],'anonymitySetsizeHorAll','anonymitySetsizeHorSingle')
senderAnonymityHor=anonymitySetsizeHorAll;

load(['sourceAnonymityStoMforstored1000' fileEnding]','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll','anonymityComparisonAll','anonymitySetsizePHIAllSingle','anonymitySetsizeDPHIAllSingle','anonymityComparisonAllSingle')
senderAnonymityPHIStoM=anonymitySetsizePHIAll;
senderAnonymityDPHIStoM=anonymitySetsizeDPHIAll;
load(['sourceAnonymityWtoDforstored1000' fileEnding],'anonymitySetsizePHIAll','anonymitySetsizeDPHIAll','edgetypeArrayAll');
senderAnonymityPHIWoD=anonymitySetsizePHIAll;
senderAnonymityDPHIWoD=anonymitySetsizeDPHIAll;
 
% W to M
load('midwayNodePosition','midwayNodePosition');
senderAnonymityPHIWtoM=zeros(1000,10);
senderAnonymityDPHIWtoM=zeros(1000,10);
senderAnonymityPHIWtoM(1:1000,1:6)=senderAnonymityPHIStoM(1:1000,midwayNodePosition:midwayNodePosition+5);
senderAnonymityDPHIWtoM(1:1000,1:6)=senderAnonymityDPHIStoM(1:1000,midwayNodePosition:midwayNodePosition+5);


% for PHI and dPHI we have to remove W to M
senderAnonymityPHIStoW=zeros(1000,10);
senderAnonymityDPHIStoW=zeros(1000,10);


senderAnonymityPHIStoW(1:1000,1:midwayNodePosition)=senderAnonymityPHIStoM(1:1000,1:midwayNodePosition);
senderAnonymityDPHIStoW(1:1000,1:midwayNodePosition)=senderAnonymityDPHIStoM(1:1000,1:midwayNodePosition);

% we also once plot sender anonymity for dPHI vs PHI for all nodes.
senderAnonymityPHIStoMtoD=zeros(1000,15);
senderAnonymityDPHIStoMtoD=zeros(1000,15);


% Now we add W to D. W is not included in anonymitySetsizePHIWtoD

for(i=1:1000)
    emptyEntries=find(senderAnonymityPHIStoW(i,:)==0);
    senderAnonymityPHIStoMtoD(i,emptyEntries(1):emptyEntries(1)+4)=senderAnonymityPHIWoD(i,1:5);

    emptyEntries=find(senderAnonymityDPHIStoW(i,:)==0);
    senderAnonymityDPHIStoMtoD(i,emptyEntries(1):emptyEntries(1)+4)=senderAnonymityDPHIWoD(i,1:5);
    
    
    
end

% we also have computed s to m source anonymity without using
% valley-freeness
%load('sourceAnonymityStoMNoBGBforRandom1000IP.mat','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll')
%senderAnonymityNoBgpPHIStoM=anonymitySetsizePHIAll;
%senderAnonymityNoBgpDPHIStoM=anonymitySetsizeDPHIAll;


% we also have computed s to m source anonymity without using
% valley-freeness
load('sourceAnonymityNoShortestPathStoMforstored1000IP.mat','anonymitySetsizePHIAll','anonymitySetsizeDPHIAll')
senderAnonymityNoShortestRoutePHIStoM=anonymitySetsizePHIAll;
senderAnonymityNoShortestRouteDPHIStoM=anonymitySetsizeDPHIAll;


% Now we can start plotting


%% plotting S to M all distances (PETs Fugure 5 a and b (by switching the plotWithIP variable to 0)
resultList={senderAnonymityPHIStoM,senderAnonymityDPHIStoM,senderAnonymityLAP,senderAnonymityLAP3,senderAnonymityHor};

titleFirst="CDF of sender anonymity for s to M";
titleSecond="all distances";
experimentNames={"PHI","dPHI","LAP (no VSS)","LAP (VSS=3)","HORNET"};
numOfResults=5;
fileName=['FiguresenderAnonymityStoM'  figureEnding];
isIP=plotWithIP;
plotCDFComparison(resultList,numOfResults,experimentNames,titleFirst,titleSecond,plotWithIP,saveFigures,fileName,1,0)

%% plotting S to M different distances (Not in PETS paper)
resultList={senderAnonymityPHIStoM,senderAnonymityDPHIStoM,senderAnonymityLAP,senderAnonymityLAP3,senderAnonymityHor};

titleFirst="CDF of sender anonymity for s to M";
titleSecond="distance from s=";
experimentNames={"PHI","dPHI","LAP (no VSS)","LAP (VSS=3","HORNET"};
numOfResults=5;
fileName=['FiguresenderAnonymityStoM'  figureEnding];
isIP=plotWithIP;
plotCDFComparison(resultList,numOfResults,experimentNames,titleFirst,titleSecond,plotWithIP,saveFigures,fileName,0,1)

%% plotting W to D all distances only PHI (Not in PETs paper)
resultList={senderAnonymityPHIWoD,senderAnonymityDPHIWoD};

titleFirst="CDF of sender anonymity for W to d";
titleSecond=" ";
experimentNames={"PHI","dPHI"};
numOfResults=2;
fileName=['FiguresenderAnonymityWtoDonlyPhi'  figureEnding];
isIP=plotWithIP;
plotCDFComparison(resultList,numOfResults,experimentNames,titleFirst,titleSecond,plotWithIP,saveFigures,fileName,1,1)


%% plotting W to D and W to M all distances only PHI (PETs Figure 5 c )
resultList={senderAnonymityPHIWoD,senderAnonymityDPHIWoD,senderAnonymityPHIWtoM,senderAnonymityDPHIWtoM,senderAnonymityPHIStoW,senderAnonymityDPHIStoW};

titleFirst="CDF of sender anonymity";
titleSecond="for different path segments";
experimentNames={"PHI (W to d)","dPHI (W to d)","PHI (W to M)","dPHI (W to M)","PHI (s to W)","dPHI (s to W)"};
numOfResults=6;
fileName=['FiguresenderAnonymityWtoDandWtoM'  figureEnding];
isIP=plotWithIP;
plotCDFComparison(resultList,numOfResults,experimentNames,titleFirst,titleSecond,plotWithIP,saveFigures,fileName,1,0)


%% plotting s to m different routing policies (PETs Figure 5 d)
resultList={senderAnonymityPHIStoM,senderAnonymityDPHIStoM,senderAnonymityNoBgpPHIStoM,senderAnonymityNoBgpDPHIStoM,senderAnonymityNoShortestRoutePHIStoM,senderAnonymityNoShortestRouteDPHIStoM};

titleFirst="CDF of sender anonymity for s to M";
titleSecond=" ";
experimentNames={"PHI","dPHI","PHI (no valley freeness)","dPHI (no valley freeness)","PHI (no shortest path)","dPHI (no shortest path)"};
numOfResults=6;
fileName=['FiguresenderAnonymityNoBgpStoM'  figureEnding];
isIP=plotWithIP;
plotCDFComparison(resultList,numOfResults,experimentNames,titleFirst,titleSecond,plotWithIP,saveFigures,fileName,1,0)

