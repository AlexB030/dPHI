% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

function [shortestTree treeDistances] = shortestBGPtreeDestination(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,destination)
% This function is identical to shortestBGPtreeSource, the only difference
% is nodes in a path are not appended at the end but inserted in the front.

%load('nographFrom2014withAll.mat','listOfNodes','sourceCellC','sourceCellP','sourceCellPtoP','sourceListPtoC','destinationListPtoC','sourceListPtoP','destinationListPtoP')
numOfNodes=size(listOfNodes,1);

%with array lookup it takes 6.4 seconds
%lets test what it takes with cell lookup;

nodesToVisitC=[];
nodesToVisitP=[];
nodesToVisitPP=[];
nextNodesToVisitC=[];
nextNodesToVisitP=[];
nextNodesToVisitPP=[];

treeCtoP=cell(numOfNodes,1);
treePtoC=cell(numOfNodes,1);
distancesCtoP=ones(numOfNodes,1)*inf;
distancesPtoC=ones(numOfNodes,1)*inf;

%we start at the destination node.
nodesToVisitC(1)=destination;
counterToVisitC=1;
nextCounterToVisitC=0;
counterToVisitP=0;
nextCounterToVisitP=0;

treeCtoP{destination}=[destination];

while(counterToVisitC>0 || counterToVisitP>0)
    %We first traverse from the client nodes, then peer-peer nodes than
    %peer and add new nodes that can be reached
    for(currNodePointer=1:counterToVisitC)
        currPath=treeCtoP{nodesToVisitC(currNodePointer)};
        pathlength=size(currPath,2)+1;
        %Find all destination to source links for node nodesToVisitC(currNodePointer)

      %  nodesToCheckC=sourceListPtoC(destinationListPtoC==nodesToVisitC(currNodePointer));
        nodesToCheckC=sourceCellC{nodesToVisitC(currNodePointer)};
       % nodesToCheckP=destinationListPtoC(sourceListPtoC==nodesToVisitC(currNodePointer));
        nodesToCheckP=sourceCellP{nodesToVisitC(currNodePointer)};

        % now also add possible peer edges, note that after a peer edge
        % no second peer to peer edge is allowed so we can treat is as
        % if it would have been a peer to customer edge
%            nodesToCheckP=[sourceListPtoP(destinationListPtoP==nodesToVisitC(currNodePointer));destinationListPtoP(sourceListPtoP==nodesToVisitC(currNodePointer))];
        nodesToCheckP=[nodesToCheckP; sourceCellPtoP{nodesToVisitC(currNodePointer)}];

        %   disp(['CtoP, depth:' num2str(pathlength) ' in C:' num2str(size(nodesToCheckC,1)) ' in P:' num2str(size(nodesToCheckP,1))])

        %We start by checking all client to peer links and add them if they
        %are shortest
        for(i=1:size(nodesToCheckC,1))
            if(distancesCtoP(nodesToCheckC(i))>pathlength)
                treeCtoP{nodesToCheckC(i)}=[nodesToCheckC(i) currPath];
                nextCounterToVisitC=nextCounterToVisitC+1;
                nextNodesToVisitC(nextCounterToVisitC)=nodesToCheckC(i);
                distancesCtoP(nodesToCheckC(i))=pathlength;
            end
        end           

%             %We now add all new Peer-To-Customer Links but store them in the
%             %peer array (custmer to peer are forbidden for them
         for(i=1:size(nodesToCheckP,1))
             if(distancesPtoC(nodesToCheckP(i))>pathlength)
                 treePtoC{nodesToCheckP(i)}=[nodesToCheckP(i) currPath];
                 nextCounterToVisitP=nextCounterToVisitP+1;
                 nextNodesToVisitP(nextCounterToVisitP)=nodesToCheckP(i);
                 distancesPtoC(nodesToCheckP(i))=pathlength;
             end
         end   
     end

%         % Done with all nodes that were reached via Client to Peer and peer to peer. Now we
%         % check Peer to client but for those client to peer and peer to peer links are invalid.
      for(currNodePointer=1:size(nodesToVisitP,2))
         currPath=treePtoC{nodesToVisitP(currNodePointer)};
         pathlength=size(currPath,2)+1;
   %     nodesToCheckP=destinationListPtoC(sourceListPtoC==nodesToVisitP(currNodePointer));
        nodesToCheckP=sourceCellP{nodesToVisitP(currNodePointer)};

%          disp(['PtoC, depth:' num2str(pathlength) ' in C:' num2str(size(nodesToCheckC,1)) ' in P:' num2str(size(nodesToCheckP,1))])         
         for(i=1:size(nodesToCheckP,1))
             if(distancesPtoC(nodesToCheckP(i))>pathlength)
                 treePtoC{nodesToCheckP(i)}=[nodesToCheckP(i) currPath];
                 nextCounterToVisitP=nextCounterToVisitP+1;
                 nextNodesToVisitP(nextCounterToVisitP)=nodesToCheckP(i);
                 distancesPtoC(nodesToCheckP(i))=pathlength;

             end
         end 
      end
      % we are done for this depth. Now we move to the next depth.
    nodesToVisitC=nextNodesToVisitC;
    nodesToVisitP=nextNodesToVisitP;
    counterToVisitC=nextCounterToVisitC;
    nextCounterToVisitC=0;
    counterToVisitP=nextCounterToVisitP;
    nextCounterToVisitP=0;
    nextNodesToVisitC=[];
    nextNodesToVisitP=[];
  %  toc
  %  disp(['Done with depth:' num2str(depth)])
  %  depth=depth+1;
end

shortestTree=cell(numOfNodes,1);
chooseCtoP=find(distancesCtoP<=distancesPtoC);
choosePtoC=find(distancesPtoC<distancesCtoP);

shortestTree(chooseCtoP)=treeCtoP(chooseCtoP);
shortestTree(choosePtoC)=treePtoC(choosePtoC);

treeDistances(choosePtoC)=distancesPtoC(choosePtoC);
treeDistances(chooseCtoP)=distancesCtoP(chooseCtoP);
%disp(['Reachable Nodes;'  num2str(sum(treeDistances<inf))])
  %  [treeOut testDist]=shortestpathtree(G,source,'all');
   % [treeOut testDist2]=shortestpathtree(G,'all',source);
   %     disp(['Treesearch:'  num2str(sum(testDist<inf))])

