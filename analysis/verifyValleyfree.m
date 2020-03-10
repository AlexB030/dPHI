% Authors: Georg T. Becker and Alexander Bajic
% This code was published as part of the PETs 2020 publication 
%"dPHI: An improved high-speed network-layer anonymity protocol"
% The complete code, copyright and readme can be found at https://github.com/AlexB030/dPHI
% For questions, contact georg.becker@ ruhr-uni-bochum.de

function [isValleyFree errorType] = verifyValleyfree(listOfNodes,sourceCellC,sourceCellP,sourceCellPtoP,pathToCheck)
% This function verifies if the path "pathToCheck" is valley free.
%This is % used to check if due to the midway node selection the valley freenes is
% broken. We think it might happen but is very unlikely (only due to two
% peer-to-peer links in a row.


protocolState=1; %1: client to peer, 2: peer to peer, 3: peer to client
isValleyFree=1;
errorType=[];
for(i=1:size(pathToCheck,2)-1)
    if(protocolState==1)
        %either client to peer, peer to peer or peer to client is allowed
        possibleDestinations=sourceCellC{pathToCheck(i)};
        if(sum(possibleDestinations==pathToCheck(i+1))==0)
            % no match iin client to peer. Lets check peer to peer and peer
            % to client
             possibleDestinations=sourceCellPtoP{pathToCheck(i)};
            if(sum(possibleDestinations==pathToCheck(i+1))==1)
                protocolState=2; % it was a per to peer so we enter next phase, useing 2 to indicate that it was peer to peer
            else
                possibleDestinations=sourceCellP{pathToCheck(i)};
                if(sum(possibleDestinations==pathToCheck(i+1))==1)
                    protocolState=3; % it was a per to client so we enter next phase with 3 to indicate it was peer to client
                else
                    isValleyFree=0;
                    errorType="no path index:"+num2str(i); %This is no path at all
                    break;
                end
            end
        end
    else
        %only peer to client is allowed
        possibleDestinations=sourceCellP{pathToCheck(i)};
        if(sum(possibleDestinations==pathToCheck(i+1))==0)
            %Something is wrong, lets check what the problem was
             possibleDestinations=sourceCellPtoP{pathToCheck(i)};
            if(sum(possibleDestinations==pathToCheck(i+1))==1)
               if(protocolState==2)
                   isValleyFree=0;
                   errorType="two peer to peer in a row index:"+num2str(i); %This is no path at all
                   break;
               else
                   isValleyFree=0;
                   errorType="peer-to-peer in phase 3 index:"+num2str(i); %This is no path at all
                   break;
               end
            else
                possibleDestinations=sourceCellC{pathToCheck(i)};
                if(sum(possibleDestinations==pathToCheck(i+1))==1)
                   isValleyFree=0;
                   errorType="c to p in phase 3"; %This is no path at all
                   break;
                else
                   isValleyFree=0;
                   errorType="no path at index:"+num2str(i); %This is no path at all
                   break;
                end
            end
        end
    end
end

