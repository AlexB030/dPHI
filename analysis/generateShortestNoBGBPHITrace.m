% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

function [pathSM,pathWtoD,pathWtoM,midwayNode,hasFailed] = generateShortestNoBGBPHITrace(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,source,destination,helperNode)
%Generates a PHI trace from source to destination via the helper node.
%Allways the shortest valley-free path is chosen for routes between Source
%and helper node, choosing midway node, midway node to destination. 

%load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP')

numOfNodes=size(listOfNodes,1);


%Find Path from S to helper node
%treeToHelper=shortestpathtree(G,'all',helperNode,'OutputForm','cell');
[treeToHelper treeDistancesHelper] = shortestAllNoBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,helperNode);

%Check if the helper node can be reached. If not, no session can be
%established
pathSM=treeToHelper{source}(1,:);
if(isempty(pathSM))
    hasFailed=1;
    pathSM=[];
    pathWtoD=[];
    pathWtoM=[];
    midwayNode=[];
    disp(['Setup Failure! helperNode not found']);
    return;
end




% if(min(pathSMshortest==pathSM)==0)
%     disp('shortest and tree are different')
% end

%% now do the backtracking to find midwayNode
foundMidway=0;
currNode=size(pathSM,2);

%pathWtoDshortest=shortestpath(G,pathSM(currNode),destination);
%treeToD=shortestpathtree(G,'all',destination,'OutputForm','cell');
[treeToD treeDistancesD] = shortestAllNoBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,destination);
pathWtoD=treeToD{pathSM(currNode)}(1,:);
%Check if the helper node can be reached. If not, no session can be
%established
if(isempty(pathWtoD))
    hasFailed=1;
    pathSM=[];
    pathWtoD=[];
    pathWtoM=[];
    midwayNode=[];
    disp(['Setup Failure! D not found']);
    return;
end


while(foundMidway==0&&currNode>1)
    
    pathPrevToD=treeToD{pathSM(currNode-1)}(1,:);
    if(max(pathPrevToD==pathSM(currNode))==0)
        %there is a shortest path, backtrack
        currNode=currNode-1;
        pathWtoD=pathPrevToD;
    else
        foundMidway=1;
        midwayNode=pathSM(currNode);
        pathWtoM=pathSM(currNode+1:size(pathSM,2));
    end
end

if(foundMidway==0)
    hasFailed=1;
        pathWtoM=[];
    midwayNode=0;
    disp(['Setup Failure!']);
else
    hasFailed=0;

end

end

